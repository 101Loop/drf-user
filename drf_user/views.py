from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from rest_framework.generics import RetrieveUpdateAPIView

from django.utils.text import gettext_lazy as _


class Register(CreateAPIView):
    """
    Register a new user to the system.
    """
    from .serializers import UserSerializer
    from rest_framework.permissions import AllowAny
    from rest_framework.renderers import JSONRenderer

    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        from .models import User

        user = User.objects.create_user(username=serializer.validated_data['username'],
                                        email=serializer.validated_data['email'],
                                        name=serializer.validated_data['name'],
                                        password=serializer.validated_data['password'],
                                        mobile=serializer.validated_data['mobile'])
        serializer = self.get_serializer(user)


class Login(APIView):
    """
    This is used to Login into system. The data required are 'username' and 'password'.
    In 'username' user can provide either username or mobile or email address.
    """
    from rest_framework_jwt.serializers import JSONWebTokenSerializer
    from rest_framework.permissions import AllowAny
    from rest_framework.renderers import JSONRenderer

    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)
    serializer_class = JSONWebTokenSerializer

    def validated(self, serialized_data, *args, **kwargs):
        from rest_framework_jwt.settings import api_settings

        from datetime import datetime

        from .models import AuthTransaction

        from drfaddons.add_ons import get_client_ip

        from rest_framework.response import Response

        user = serialized_data.object.get('user') or self.request.user
        token = serialized_data.object.get('token')
        response_data = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER(token, user, self.request)
        response = Response(response_data)
        if api_settings.JWT_AUTH_COOKIE:
            expiration = (datetime.utcnow() +
                          api_settings.JWT_EXPIRATION_DELTA)
            response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                token,
                                expires=expiration,
                                httponly=True)

        user.last_login = datetime.now()
        user.save()

        AuthTransaction(user=user, ip_address=get_client_ip(self.request), token=token,
                        session=user.get_session_auth_hash()).save()

        return response

    def post(self, request):
        from drfaddons.add_ons import JsonResponse

        from rest_framework import status

        serialized_data = self.serializer_class(data=request.data)
        if serialized_data.is_valid():
            return self.validated(serialized_data=serialized_data)
        else:
            return JsonResponse(serialized_data.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class VerifyOTP(CreateAPIView):
    """
    Sends an OTP to a value.
    Also used to verify an OTP
    'prop': Can be email or mobile
    'destination': A valid email address or mobile number
    'otp': An otp, in case of verification
    'email': Temporarily here. OTP will be sent here in case of mobile.
    """
    from .serializers import SendOTPSerializer

    serializer_class = SendOTPSerializer

    def create(self, request, *args, **kwargs):
        from rest_framework.response import Response
        from rest_framework.exceptions import NotFound
        from rest_framework.mixins import status

        from .models import OTPValidation
        from .utils import validate_otp

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if 'otp' in serializer.validated_data.keys():
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        else:
            try:
                otpobject = OTPValidation.objects.get(destination=request.data.get('destination'))
            except OTPValidation.DoesNotExists:
                raise NotFound(detail=_('Provided destination has not OTP Validation request, yet.'))
            else:

                otpobject.validate_attempt -= 1

                if validate_otp(str(otpobject.destination), int(request.data.get('otp'))):
                    return Response(data={'OTP': [_('OTP Validated successfully!'), ]}, status=status.HTTP_202_ACCEPTED)

    def perform_create(self, serializer):
        from .utils import generate_otp, send_otp

        from rest_framework.exceptions import APIException

        prop = serializer.validated_data['prop']
        destination = serializer.validated_data['destination']

        otpobj = generate_otp(prop, destination)

        sentotp = send_otp(prop, destination, otpobj, serializer.validated_data['email'])

        if sentotp['success']:
            otpobj.send_counter += 1
            otpobj.save()
        else:
            raise APIException(detail=_('A Server Error occurred: ' + sentotp['message']))

        serializer = self.get_serializer(otpobj)


class CheckUnique(APIView):
    """
    This view checks if the given property -> value pair is unique (or doesn't exists yet)
    'prop': A property to check for uniqueness (username/email/mobile)
    'value': Value against property which is to be checked for.
    """
    from .serializers import CheckUniqueSerializer
    from rest_framework.permissions import AllowAny
    from rest_framework.renderers import JSONRenderer

    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)
    serializer_class = CheckUniqueSerializer

    def validated(self, serialized_data, *args, **kwargs):
        from .utils import check_unique

        from rest_framework.mixins import status

        return {'unique': check_unique(serialized_data.validated_data['prop'],
                                       serialized_data.validated_data['value'])}, status.HTTP_200_OK

    def post(self, request):
        from drfaddons.add_ons import JsonResponse
        from rest_framework import status

        serialized_data = self.serializer_class(data=request.data)
        if serialized_data.is_valid():
            return JsonResponse(self.validated(serialized_data=serialized_data))
        else:
            return JsonResponse(serialized_data.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class LoginOTP(APIView):
    from .serializers import LoginOTPSerializer

    serializer_class = LoginOTPSerializer

    def validated(self, serialized_data, *args, **kwargs):
        from .utils import generate_otp, send_otp, validate_otp, login_user
        from .models import User

        from rest_framework.exceptions import NotFound, APIException
        from rest_framework.mixins import status

        otp = serialized_data.validated_data['otp']
        destination = serialized_data.validated_data['destination']
        prop = serialized_data.validated_data['prop']

        if prop == 'M':
            try:
                user = User.objects.get(mobile=destination)
            except User.DoesNotExist:
                user = None
        else:
            try:
                user = User.objects.get(email=destination)
            except User.DoesNotExist:
                user = None

        if user is None:
            raise NotFound(_('No user exists with provided details'))

        else:
            if otp is None:
                otp_obj = generate_otp(prop, destination)
                data = send_otp(prop, destination, otp_obj, user.email)

                if data['success']:
                    otp_obj.send_counter += 1
                    otp_obj.save()

                    return data, status.HTTP_201_CREATED

                else:
                    raise APIException(detail=_('A Server Error occurred: ' + data['message']))

            else:
                validate_otp(destination, int(otp))
                return login_user(user, self.request)

    def post(self, request):
        from drfaddons.add_ons import JsonResponse
        from rest_framework import status

        serialized_data = self.serializer_class(data=request.data)
        if serialized_data.is_valid():
            return JsonResponse(self.validated(serialized_data=serialized_data))
        else:
            return JsonResponse(serialized_data.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class RetrieveUpdateUserAccountView(RetrieveUpdateAPIView):
    """
    This view is to update a user profile.
    """
    from .serializers import UserSerializer
    from .models import User

    from rest_framework.permissions import IsAuthenticated

    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)
    lookup_field = 'created_by'

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        if 'password' in request.data.keys():
            self.request.user.set_password(request.data.pop('password'))
            self.request.user.save()

        return super(RetrieveUpdateUserAccountView, self).update(request, *args, **kwargs)
