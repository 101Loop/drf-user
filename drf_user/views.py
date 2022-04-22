"""Views for drf-user"""
from django.conf import settings
from django.utils import timezone
from django.utils.text import gettext_lazy as _
from drfaddons.utils import JsonResponse
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.views import TokenRefreshView

from drf_user.models import AuthTransaction
from drf_user.models import User
from drf_user.serializers import CheckUniqueSerializer
from drf_user.serializers import CustomTokenObtainPairSerializer
from drf_user.serializers import OTPLoginRegisterSerializer
from drf_user.serializers import OTPSerializer
from drf_user.serializers import PasswordResetSerializer
from drf_user.serializers import UserSerializer
from drf_user.utils import check_unique
from drf_user.utils import generate_otp
from drf_user.utils import get_client_ip
from drf_user.utils import login_user
from drf_user.utils import send_otp
from drf_user.utils import validate_otp
from drf_user.variables import EMAIL
from drf_user.variables import MOBILE


class RegisterView(CreateAPIView):
    """
    Register View

    Register a new user to the system.
    The data required are username, email, name, password and mobile (optional).
    """

    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        """Override perform_create to create user"""
        data = {
            "username": serializer.validated_data["username"],
            "email": serializer.validated_data["email"],
            "name": serializer.validated_data["name"],
            "password": serializer.validated_data["password"],
        }
        try:
            data["mobile"] = serializer.validated_data["mobile"]
        except KeyError:
            if not settings.USER_SETTINGS["MOBILE_OPTIONAL"]:
                raise ValidationError({"error": "Mobile is required."})
        return User.objects.create_user(**data)


class LoginView(APIView):
    """
    Login View

    This is used to Login into system.
    The data required are 'username' and 'password'.

    username -- Either username or mobile or email address.
    password -- Password of the user.
    """

    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        """
        Process a login request via username/password.
        """
        serializer = self.serializer_class(data=request.data)

        serializer.is_valid(raise_exception=True)

        # if data is valid then create a record in auth transaction model
        user = serializer.user
        token = serializer.validated_data.get("access")
        refresh_token = serializer.validated_data.get("refresh")

        AuthTransaction(
            created_by=user,
            token=str(token),
            refresh_token=str(refresh_token),
            ip_address=get_client_ip(self.request),
            session=user.get_session_auth_hash(),
            expires_at=timezone.now() + api_settings.ACCESS_TOKEN_LIFETIME,
        ).save()

        # For backward compatibility, returning custom response
        # as simple_jwt returns `access` and `refresh`
        resp = {
            "refresh_token": str(refresh_token),
            "token": str(token),
            "session": user.get_session_auth_hash(),
        }
        return Response(resp, status=status.HTTP_200_OK)


class CheckUniqueView(APIView):
    """
    Check Unique API View

    This view checks if the given property -> value pair is unique (or
    doesn't exists yet)
    'prop' -- A property to check for uniqueness (username/email/mobile)
    'value' -- Value against property which is to be checked for.
    """

    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)
    serializer_class = CheckUniqueSerializer

    def validated(self, serialized_data, *args, **kwargs):
        """Validates the response"""
        return (
            {
                "unique": check_unique(
                    serialized_data.validated_data["prop"],
                    serialized_data.validated_data["value"],
                )
            },
            status.HTTP_200_OK,
        )

    def post(self, request):
        """Overrides post method to validate serialized data"""
        serialized_data = self.serializer_class(data=request.data)
        if serialized_data.is_valid():
            return JsonResponse(self.validated(serialized_data=serialized_data))
        else:
            return JsonResponse(
                serialized_data.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY
            )


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
    """

    permission_classes = (AllowAny,)
    serializer_class = OTPSerializer

    def post(self, request, *args, **kwargs):
        """Overrides post method to validate serialized data"""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        destination = serializer.validated_data.get("destination")
        prop = serializer.validated_data.get("prop")
        user = serializer.validated_data.get("user")
        email = serializer.validated_data.get("email")
        is_login = serializer.validated_data.get("is_login")

        if "verify_otp" in request.data.keys():
            if validate_otp(destination, request.data.get("verify_otp")):
                if is_login:
                    return Response(
                        login_user(user, self.request), status=status.HTTP_202_ACCEPTED
                    )
                else:
                    return Response(
                        data={
                            "OTP": [
                                _("OTP Validated successfully!"),
                            ]
                        },
                        status=status.HTTP_202_ACCEPTED,
                    )
        else:
            otp_obj = generate_otp(prop, destination)
            sentotp = send_otp(destination, otp_obj, email)

            if sentotp["success"]:
                otp_obj.send_counter += 1
                otp_obj.save()

                return Response(sentotp, status=status.HTTP_201_CREATED)
            else:
                raise APIException(
                    detail=_("A Server Error occurred: " + sentotp["message"])
                )


class RetrieveUpdateUserAccountView(RetrieveUpdateAPIView):
    """
    Retrieve Update User Account View

    get: Fetch Account Details
    put: Update all details
    patch: Update some details
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)
    lookup_field = "created_by"

    def get_object(self):
        """Fetches user from request"""

        return self.request.user

    def update(self, request, *args, **kwargs):
        """Updates user's password"""

        response = super(RetrieveUpdateUserAccountView, self).update(
            request, *args, **kwargs
        )
        # we need to set_password after save the user otherwise it'll save the raw_password in db. # noqa
        if "password" in request.data.keys():
            self.request.user.set_password(request.data["password"])
            self.request.user.save()
        return response


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
    """

    permission_classes = (AllowAny,)
    renderer_classes = (JSONRenderer,)
    parser_classes = (JSONParser,)
    serializer_class = OTPLoginRegisterSerializer

    def post(self, request, *args, **kwargs):
        """Overrides post method to validate serialized data"""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        verify_otp = serializer.validated_data.get("verify_otp", None)
        name = serializer.validated_data.get("name")
        mobile = serializer.validated_data.get("mobile")
        email = serializer.validated_data.get("email")
        user = serializer.validated_data.get("user", None)

        if verify_otp:
            if validate_otp(email, verify_otp) and not user:
                user = User.objects.create_user(
                    name=name,
                    mobile=mobile,
                    email=email,
                    username=mobile,
                    password=User.objects.make_random_password(),
                )
                user.is_active = True
                user.save()
            return Response(
                login_user(user, self.request), status=status.HTTP_202_ACCEPTED
            )

        else:
            otp_obj_email = generate_otp(EMAIL, email)
            otp_obj_mobile = generate_otp(MOBILE, mobile)

            # Set same OTP for both Email & Mobile
            otp_obj_mobile.otp = otp_obj_email.otp
            otp_obj_mobile.save()

            # Send OTP to Email & Mobile
            sentotp_email = send_otp(email, otp_obj_email, email)
            sentotp_mobile = send_otp(mobile, otp_obj_mobile, email)

            message = {}

            if sentotp_email["success"]:
                otp_obj_email.send_counter += 1
                otp_obj_email.save()
                message["email"] = {"otp": _("OTP has been sent successfully.")}
            else:
                message["email"] = {
                    "otp": _(f'OTP sending failed {sentotp_email["message"]}')
                }

            if sentotp_mobile["success"]:
                otp_obj_mobile.send_counter += 1
                otp_obj_mobile.save()
                message["mobile"] = {"otp": _("OTP has been sent successfully.")}
            else:
                message["mobile"] = {
                    "otp": _(f'OTP sending failed {sentotp_mobile["message"]}')
                }

            if sentotp_email["success"] or sentotp_mobile["success"]:
                curr_status = status.HTTP_201_CREATED
            else:
                raise APIException(
                    detail=_("A Server Error occurred: " + sentotp_mobile["message"])
                )

            return Response(data=message, status=curr_status)


class PasswordResetView(APIView):
    """This API can be used to reset a user's password.

    Usage: First send an otp to the user by making an
    API call to `api/user/otp/` with `is_login` parameter value false.
    """

    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        """Overrides post method to validate OTP and reset password"""
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.get(email=serializer.validated_data["email"])

        if validate_otp(
            serializer.validated_data["email"], serializer.validated_data["otp"]
        ):
            # OTP Validated, Change Password
            user.set_password(serializer.validated_data["password"])
            user.save()
            return JsonResponse(
                content="Password Updated Successfully.",
                status=status.HTTP_202_ACCEPTED,
            )


class UploadImageView(APIView):
    """This API can be used to upload a profile picture for user.

    usage: Create a multipart request to this API, with your image
    attached to `profile_image` parameter.
    """

    from .models import User
    from .serializers import ImageSerializer
    from rest_framework.permissions import IsAuthenticated
    from rest_framework.parsers import MultiPartParser

    queryset = User.objects.all()
    serializer_class = ImageSerializer
    permission_classes = (IsAuthenticated,)
    parser_class = (MultiPartParser,)

    def post(self, request, *args, **kwargs):
        """Validate serializer and upload user profile image"""

        from .serializers import ImageSerializer
        from rest_framework.response import Response
        from rest_framework import status

        image_serializer = ImageSerializer(data=request.data)

        if not image_serializer.is_valid():
            return Response(image_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        image_serializer.update(
            instance=request.user, validated_data=image_serializer.validated_data
        )
        return Response(
            {"detail": "Profile Image Uploaded."}, status=status.HTTP_201_CREATED
        )


class CustomTokenRefreshView(TokenRefreshView):
    """
    Subclassing TokenRefreshView so that we can update
    AuthTransaction model when access token is updated
    """

    def post(self, request, *args, **kwargs):
        """
        Process request to generate new access token using
        refresh token.
        """
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        token = serializer.validated_data.get("access")

        auth_transaction = AuthTransaction.objects.get(
            refresh_token=request.data["refresh"]
        )
        auth_transaction.token = token
        auth_transaction.expires_at = (
            timezone.now() + api_settings.ACCESS_TOKEN_LIFETIME
        )
        auth_transaction.save(update_fields=["token", "expires_at"])

        return Response({"token": str(token)}, status=status.HTTP_200_OK)
