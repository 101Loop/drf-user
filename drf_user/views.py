from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from rest_framework.generics import RetrieveUpdateAPIView

from django.utils.text import gettext_lazy as _


class RegisterView(CreateAPIView):
    """
    Register View

    Register a new user to the system.
    The data required are username, email, name, password and mobile.

    Author: Himanshu Shankar (https://himanshus.com)
            Aditya Gupta (https://github.com/ag93999)
    """
    from .serializers import UserSerializer
    from rest_framework.permissions import AllowAny
    from rest_framework.renderers import JSONRenderer

    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        from .models import User

        user = User.objects.create_user(
            username=serializer.validated_data['username'],
            email=serializer.validated_data['email'],
            name=serializer.validated_data['name'],
            password=serializer.validated_data['password'],
            mobile=serializer.validated_data['mobile'])
        serializer = self.get_serializer(user)


class LoginView(APIView):
    """
    Login View

    This is used to Login into system.
    The data required are 'username' and 'password'.

    username -- Either username or mobile or email address.
    password -- Password of the user.

    Author: Himanshu Shankar (https://himanshus.com)
            Aditya Gupta (https://github.com/ag93999)
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

        from drfaddons.utils import get_client_ip

        from rest_framework.response import Response

        user = serialized_data.object.get('user') or self.request.user
        token = serialized_data.object.get('token')
        response_data = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER(token, user,
                                                                  self.request)
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

        AuthTransaction(created_by=user, token=token,
                        ip_address=get_client_ip(self.request),
                        session=user.get_session_auth_hash()).save()

        return response

    def post(self, request):
        from drfaddons.utils import JsonResponse

        from rest_framework import status

        serialized_data = self.serializer_class(data=request.data)
        if serialized_data.is_valid():
            return self.validated(serialized_data=serialized_data)
        else:
            return JsonResponse(serialized_data.errors,
                                status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class CheckUniqueView(APIView):
    """
    Check Unique API View

    This view checks if the given property -> value pair is unique (or
    doesn't exists yet)
    'prop' -- A property to check for uniqueness (username/email/mobile)
    'value' -- Value against property which is to be checked for.

     Author: Himanshu Shankar (https://himanshus.com)
            Aditya Gupta (https://github.com/ag93999)
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

        return (
            {'unique': check_unique(serialized_data.validated_data['prop'],
                                    serialized_data.validated_data['value'])},
            status.HTTP_200_OK)

    def post(self, request):
        from drfaddons.utils import JsonResponse
        from rest_framework import status

        serialized_data = self.serializer_class(data=request.data)
        if serialized_data.is_valid():
            return JsonResponse(self.validated(
                serialized_data=serialized_data))
        else:
            return JsonResponse(serialized_data.errors,
                                status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class OTPView(APIView):
    """
    OTP Validate | OTP Login

    FROM SERIALIZER
    ----------------
    is_login -- Set is_login true if trying to login via OTP
    destination -- Required. Place where sending OTP
    email -- Fallback in case of destination is a mobile number
    verify_otp -- OTP in the 2nd step of flow

    Examples
    --------
    1. Request an OTP for verifying
    >>> {"destination": "me@himanshus.com"}
    Or for mobile number as destination
    >>> {"destination": "88xx6xx5xx", "email": "me@himanshus.com"}

    2. Send OTP to verify
    >>> {"destination": "me@himanshus.com", "verify_otp": 2930432}
    Or for mobile number as destination
    >>> {"destination": "88xx6xx5xx", "email": "me@himanshus.com",
    >>>  "verify_otp": 2930433})

    For log in, just add is_login to request
    >>> {"destination": "me@himanshus.com", "is_login": True}

    >>> {"destination": "me@himanshus.com", "is_login": True,
    >>>  "verify_otp": 1234232}

    Author: Himanshu Shankar (https://himanshus.com)
            Aditya Gupta (https://github.com/ag93999)
    """
    from .serializers import OTPSerializer

    from rest_framework.permissions import AllowAny

    permission_classes = (AllowAny, )
    serializer_class = OTPSerializer

    def post(self, request, *args, **kwargs):
        from rest_framework.response import Response
        from rest_framework.mixins import status

        from rest_framework.exceptions import APIException

        from .utils import validate_otp, login_user, generate_otp, send_otp

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        destination = serializer.validated_data.get('destination')
        prop = serializer.validated_data.get('prop')
        user = serializer.validated_data.get('user')
        email = serializer.validated_data.get('email')
        is_login = serializer.validated_data.get('is_login')

        if 'verify_otp' in request.data.keys():
            if validate_otp(destination, request.data.get('verify_otp')):
                if is_login:
                    return Response(login_user(user, self.request),
                                    status=status.HTTP_202_ACCEPTED)
                else:
                    return Response(
                        data={'OTP': [_('OTP Validated successfully!'), ]},
                        status=status.HTTP_202_ACCEPTED)
        else:
            otp_obj = generate_otp(prop, destination)
            sentotp = send_otp(destination, otp_obj, email)

            if sentotp['success']:
                otp_obj.send_counter += 1
                otp_obj.save()

                return Response(sentotp, status=status.HTTP_201_CREATED)
            else:
                raise APIException(
                    detail=_('A Server Error occurred: ' + sentotp['message']))


class RetrieveUpdateUserAccountView(RetrieveUpdateAPIView):
    """
    Retrieve Update User Account View

    get: Fetch Account Details
    put: Update all details
    patch: Update some details

    Author: Himanshu Shankar (https://himanshus.com)
            Aditya Gupta( https://github.com/ag93999)
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

        return super(RetrieveUpdateUserAccountView, self).update(request,
                                                                 *args,
                                                                 **kwargs)


class OTPLoginView(APIView):
    """
    OTP Login View

    Used to register/login to a system where User may not be required
    to pre-login but needs to login in later stage or while doing a
    transaction.

    View ensures a smooth flow by sending same OTP on mobile as well as
    email.

    name -- Required
    email -- Required
    mobile -- Required
    verify_otp -- Not Required (only when verifying OTP)

    Author: Himanshu Shankar (https://himanshus.com)
            Aditya Gupta (https://github.com/ag93999)
    """

    from rest_framework.permissions import AllowAny
    from rest_framework.renderers import JSONRenderer
    from rest_framework.parsers import JSONParser

    from .serializers import OTPLoginRegisterSerializer

    permission_classes = (AllowAny,)
    renderer_classes = (JSONRenderer,)
    parser_classes = (JSONParser,)
    serializer_class = OTPLoginRegisterSerializer

    def post(self, request, *args, **kwargs):
        from rest_framework.response import Response
        from rest_framework.mixins import status

        from rest_framework.exceptions import APIException

        from .utils import validate_otp, generate_otp, send_otp
        from .utils import login_user
        from .models import User
        from .variables import EMAIL, MOBILE

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        verify_otp = serializer.validated_data.get('verify_otp', None)
        name = serializer.validated_data.get('name')
        mobile = serializer.validated_data.get('mobile')
        email = serializer.validated_data.get('email')
        user = serializer.validated_data.get('user', None)

        message = {}

        if verify_otp:
            if validate_otp(email, verify_otp):
                if not user:
                    user = User.objects.create_user(
                        name=name, mobile=mobile, email=email, username=mobile,
                        password=User.objects.make_random_password()
                    )
                    user.is_active = True
                    user.save()
                return Response(login_user(user, self.request),
                                status=status.HTTP_202_ACCEPTED)
            return Response(data={'OTP': [_('OTP Validated successfully!'), ]},
                            status=status.HTTP_202_ACCEPTED)

        else:
            otp_obj_email = generate_otp(EMAIL, email)
            otp_obj_mobile = generate_otp(MOBILE, mobile)

            # Set same OTP for both Email & Mobile
            otp_obj_mobile.otp = otp_obj_email.otp
            otp_obj_mobile.save()

            # Send OTP to Email & Mobile
            sentotp_email = send_otp(email, otp_obj_email, email)
            sentotp_mobile = send_otp(mobile, otp_obj_mobile, email)

            if sentotp_email['success']:
                otp_obj_email.send_counter += 1
                otp_obj_email.save()
                message['email'] = {
                    'otp': _("OTP has been sent successfully.")
                }
            else:
                message['email'] = {
                    'otp':_("OTP sending failed {}".format(
                        sentotp_email['message']))
                }

            if sentotp_mobile['success']:
                otp_obj_mobile.send_counter += 1
                otp_obj_mobile.save()
                message['mobile'] = {
                    'otp': _("OTP has been sent successfully.")
                }
            else:
                message['mobile'] = {
                    'otp': _("OTP sending failed {}".format(
                        sentotp_mobile['message']))
                }

            if sentotp_email['success'] or sentotp_mobile['success']:
                curr_status = status.HTTP_201_CREATED
            else:
                raise APIException(
                    detail=_(
                        'A Server Error occurred: ' + sentotp_mobile['message']
                    ))

            return Response(data=message, status=curr_status)
