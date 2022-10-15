"""Views for drf-user"""
from typing import Optional

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import F
from django.utils import timezone
from django.utils.text import gettext_lazy as _
from rest_framework import status, serializers
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework.parsers import JSONParser
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.views import TokenRefreshView

from drf_user.models import AuthTransaction, OTPValidation
from drf_user.serializers import (
    CheckUniqueSerializer,
    CustomTokenObtainPairSerializer,
    OTPLoginRegisterSerializer,
    OTPSerializer,
    PasswordResetSerializer,
    UserSerializer,
    ImageSerializer,
)
from drf_user.utils import (
    check_unique,
    generate_otp,
    get_client_ip,
    login_user,
    validate_otp,
    send_otp,
)
from drf_user.constants import EMAIL, CoreConstants

User = get_user_model()


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
        except KeyError as e:
            if not settings.USER_SETTINGS["MOBILE_OPTIONAL"]:
                raise ValidationError({"error": "Mobile is required."}) from e
        return User.objects.create_user(**data)


class LoginView(APIView):
    """
    Login View

    This is used to Log in into system.
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

    def post(self, request):
        """Overrides post method to validate serialized data"""
        serialized_data = self.serializer_class(data=request.data)
        if serialized_data.is_valid():
            return Response(
                data={
                    "unique": check_unique(
                        serialized_data.validated_data["prop"],
                        serialized_data.validated_data["value"],
                    )
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                data=serialized_data.errors, status=status.HTTP_422_UNPROCESSABLE_ENTITY
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
        serializer: OTPSerializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        destination: str = serializer.validated_data[
            "destination"
        ]  # destination is a required field
        destination_property: str = serializer.validated_data.get("prop")  # can be email or mobile
        user: User = serializer.validated_data.get("user")
        email: Optional[str] = serializer.validated_data.get("email")
        is_login: bool = serializer.validated_data.get("is_login")

        if "verify_otp" in request.data.keys():
            if validate_otp(destination=destination, otp_val=request.data["verify_otp"]):
                if is_login:
                    return Response(login_user(user, self.request), status=status.HTTP_202_ACCEPTED)
                else:
                    return Response(
                        data={"OTP": _("OTP Validated successfully!")},
                        status=status.HTTP_202_ACCEPTED,
                    )
        else:
            otp_obj: OTPValidation = generate_otp(
                destination_property=destination_property, destination=destination
            )
            recip_mobile: Optional[str] = None
            if destination_property == CoreConstants.MOBILE_PROP:
                recip_mobile = destination

            sent_otp_resp: dict = send_otp(
                otp_obj=otp_obj, recip_email=email, recip_mobile=recip_mobile
            )

            if sent_otp_resp["success"]:
                otp_obj.send_counter = F("send_counter") + 1
                otp_obj.save(update_fields=["send_counter"])
                return Response(sent_otp_resp, status=status.HTTP_201_CREATED)

            raise serializers.ValidationError(
                detail=_(f"OTP could not be sent! {sent_otp_resp['message']}")
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

        response = super(RetrieveUpdateUserAccountView, self).update(request, *args, **kwargs)
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

        verify_otp = serializer.validated_data.get("verify_otp")
        name = serializer.validated_data["name"]
        mobile = serializer.validated_data["mobile"]
        email = serializer.validated_data["email"]
        user: User = serializer.validated_data.get("user")

        if verify_otp:
            if validate_otp(destination=email, otp_val=verify_otp) and not user:
                user = User.objects.create_user(
                    name=name,
                    mobile=mobile,
                    email=email,
                    username=mobile,
                    password=User.objects.make_random_password(),
                )
                user.is_active = True
                user.save(update_fields=["is_active"])
            return Response(login_user(user, self.request), status=status.HTTP_202_ACCEPTED)

        otp_obj: OTPValidation = generate_otp(destination_property=EMAIL, destination=email)
        # Send OTP to Email & Mobile
        sent_otp_resp: dict = send_otp(otp_obj=otp_obj, recip_email=email, recip_mobile=mobile)

        if not sent_otp_resp["success"]:
            raise serializers.ValidationError(
                detail=_(f"OTP could not be sent! {sent_otp_resp['message']}")
            )

        otp_obj.send_counter = F("send_counter") + 1
        otp_obj.save(update_fields=["send_counter"])
        message = {
            "email": {"otp": sent_otp_resp["message"]},
            "mobile_message": {"otp": sent_otp_resp["mobile_message"]},
        }

        return Response(data=message, status=status.HTTP_201_CREATED)


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
            destination=serializer.validated_data["email"],
            otp_val=serializer.validated_data["otp"],
        ):
            # OTP Validated, Change Password
            user.set_password(serializer.validated_data["password"])
            user.save()
            return Response(
                data="Password Updated Successfully.",
                status=status.HTTP_202_ACCEPTED,
            )


class UploadImageView(APIView):
    """This API can be used to upload a profile picture for user.

    usage: Create a multipart request to this API, with your image
    attached to `profile_image` parameter.
    """

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
        return Response({"detail": "Profile Image Uploaded."}, status=status.HTTP_201_CREATED)


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

        auth_transaction = AuthTransaction.objects.get(refresh_token=request.data["refresh"])
        auth_transaction.token = token
        auth_transaction.expires_at = timezone.now() + api_settings.ACCESS_TOKEN_LIFETIME
        auth_transaction.save(update_fields=["token", "expires_at"])

        return Response({"token": str(token)}, status=status.HTTP_200_OK)
