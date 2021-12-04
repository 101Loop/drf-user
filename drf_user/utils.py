"""Collection of general helper functions."""
import datetime
from typing import Dict
from typing import Optional
from typing import Union

import pytz
from django.http import HttpRequest
from django.utils import timezone
from django.utils.text import gettext_lazy as _
from drfaddons.utils import send_message
from rest_framework.exceptions import APIException
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import NotFound
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.utils import datetime_from_epoch

from drf_user import update_user_settings
from drf_user.models import AuthTransaction
from drf_user.models import OTPValidation
from drf_user.models import User

user_settings: Dict[
    str, Union[bool, Dict[str, Union[int, str, bool]]]
] = update_user_settings()
otp_settings: Dict[str, Union[str, int]] = user_settings["OTP"]


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """
    Fetches the IP address of a client from Request and
    return in proper format.
    Source: https://stackoverflow.com/a/4581997

    Parameters
    ----------
    request: django.http.HttpRequest

    Returns
    -------
    ip: str or None
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    else:
        return request.META.get("REMOTE_ADDR")


def datetime_passed_now(source: datetime.datetime) -> bool:
    """
    Compares provided datetime with current time on the basis of Django
    settings. Checks source is in future or in past. False if it's in future.
    Parameters
    ----------
    source: datetime object than may or may not be naive

    Returns
    -------
    bool

    Author: Himanshu Shankar (https://himanshus.com)
    """
    if source.tzinfo is not None and source.tzinfo.utcoffset(source) is not None:
        return source <= datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    else:
        return source <= datetime.datetime.now()


def check_unique(prop: str, value: str) -> bool:
    """
    This function checks if the value provided is present in Database
    or can be created in DBMS as unique data.
    Parameters
    ----------
    prop: str
        The model property to check for. Can be::
            email
            mobile
            username
    value: str
        The value of the property specified

    Returns
    -------
    bool
        True if the data sent is doesn't exist, False otherwise.
    Examples
    --------
    To check if test@testing.com email address is already present in
    Database
    >>> print(check_unique('email', 'test@testing.com'))
    True
    """
    user = User.objects.extra(where=[prop + " = '" + value + "'"])
    return user.count() == 0


def generate_otp(prop: str, value: str) -> OTPValidation:
    """
    This function generates an OTP and saves it into Model. It also
    sets various counters, such as send_counter,
    is_validated, validate_attempt.
    Parameters
    ----------
    prop: str
        This specifies the type for which OTP is being created. Can be::
            email
            mobile
    value: str
        This specifies the value for which OTP is being created.

    Returns
    -------
    otp_object: OTPValidation
        This is the instance of OTP that is created.
    Examples
    --------
    To create an OTP for an Email test@testing.com
    >>> print(generate_otp('email', 'test@testing.com'))
    OTPValidation object

    >>> print(generate_otp('email', 'test@testing.com').otp)
    5039164
    """
    # Create a random number
    random_number: str = User.objects.make_random_password(
        length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
    )

    # Checks if random number is unique among non-validated OTPs and
    # creates new until it is unique.
    while OTPValidation.objects.filter(otp__exact=random_number).filter(
        is_validated=False
    ):
        random_number: str = User.objects.make_random_password(
            length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
        )

    # Get or Create new instance of Model with value of provided value
    # and set proper counter.
    try:
        otp_object: OTPValidation = OTPValidation.objects.get(destination=value)
    except OTPValidation.DoesNotExist:
        otp_object: OTPValidation = OTPValidation()
        otp_object.destination = value
    else:
        if not datetime_passed_now(otp_object.reactive_at):
            return otp_object

    otp_object.otp = random_number
    otp_object.prop = prop

    # Set is_validated to False
    otp_object.is_validated = False

    # Set attempt counter to OTP_VALIDATION_ATTEMPTS, user has to enter
    # correct OTP in 3 chances.
    otp_object.validate_attempt = otp_settings["VALIDATION_ATTEMPTS"]

    otp_object.reactive_at = timezone.now() - datetime.timedelta(minutes=1)
    otp_object.save()
    return otp_object


def send_otp(value: str, otpobj: OTPValidation, recip: str) -> Dict:
    """
    This function sends OTP to specified value.
    Parameters
    ----------
    value: str
        This is the value at which and for which OTP is to be sent.
    otpobj: OTPValidation
        This is the OTP or One Time Passcode that is to be sent to user.
    recip: str
        This is the recipient to whom EMail is being sent. This will be
        deprecated once SMS feature is brought in.

    Returns
    -------

    """
    otp: str = otpobj.otp

    if not datetime_passed_now(otpobj.reactive_at):
        raise PermissionDenied(
            detail=_(f"OTP sending not allowed until: {otpobj.reactive_at}")
        )

    message = (
        f"OTP for verifying {otpobj.get_prop_display()}: {value} is {otp}."
        f"  Don't share this with anyone!"
    )

    try:
        rdata: dict = send_message(message, otp_settings["SUBJECT"], [value], [recip])
    except ValueError as err:
        raise APIException(_(f"Server configuration error occurred: {err}"))

    otpobj.reactive_at = timezone.now() + datetime.timedelta(
        minutes=otp_settings["COOLING_PERIOD"]
    )
    otpobj.save()

    return rdata


def login_user(user: User, request: HttpRequest) -> Dict[str, str]:
    """
    This function is used to login a user. It saves the authentication in
    AuthTransaction model.

    Parameters
    ----------
    user: django.contrib.auth.get_user_model
    request: HttpRequest

    Returns
    -------
    dict:
        Generated JWT tokens for user.
    """
    token: RefreshToken = RefreshToken.for_user(user)

    # Add custom claims
    if hasattr(user, "email"):
        token["email"] = user.email

    if hasattr(user, "mobile"):
        token["mobile"] = user.mobile

    if hasattr(user, "name"):
        token["name"] = user.name

    user.last_login = timezone.now()
    user.save()

    AuthTransaction(
        created_by=user,
        ip_address=get_client_ip(request),
        token=str(token.access_token),
        refresh_token=str(token),
        session=user.get_session_auth_hash(),
        expires_at=datetime_from_epoch(token["exp"]),
    ).save()

    return {
        "refresh_token": str(token),
        "token": str(token.access_token),
        "session": user.get_session_auth_hash(),
    }


def check_validation(value: str) -> bool:
    """
    This functions check if given value is already validated via OTP or not.
    Parameters
    ----------
    value: str
        This is the value for which OTP validation is to be checked.

    Returns
    -------
    bool
        True if value is validated, False otherwise.
    Examples
    --------
    To check if 'test@testing.com' has been validated!
    >>> print(check_validation('test@testing.com'))
    True

    """
    try:
        otp_object: OTPValidation = OTPValidation.objects.get(destination=value)
        return otp_object.is_validated
    except OTPValidation.DoesNotExist:
        return False


def validate_otp(value: str, otp: int) -> bool:
    """
    This function is used to validate the OTP for a particular value.
    It also reduces the attempt count by 1 and resets OTP.
    Parameters
    ----------
    value: str
        This is the unique entry for which OTP has to be validated.
    otp: int
        This is the OTP that will be validated against one in Database.

    Returns
    -------
    bool: True, if OTP is validated
    """
    try:
        # Try to get OTP Object from Model and initialize data dictionary
        otp_object: OTPValidation = OTPValidation.objects.get(
            destination=value, is_validated=False
        )
    except OTPValidation.DoesNotExist:
        raise NotFound(
            detail=_(
                "No pending OTP validation request found for provided "
                "destination. Kindly send an OTP first"
            )
        )
    # Decrement validate_attempt
    otp_object.validate_attempt -= 1

    if str(otp_object.otp) == str(otp):
        # match otp
        otp_object.is_validated = True
        otp_object.save()
        return True

    elif otp_object.validate_attempt <= 0:
        # check if attempts exceeded and regenerate otp and raise error
        generate_otp(otp_object.prop, value)
        raise AuthenticationFailed(
            detail=_("Incorrect OTP. Attempt exceeded! OTP has been reset.")
        )

    else:
        # update attempts and raise error
        otp_object.save()
        raise AuthenticationFailed(
            detail=_(
                f"OTP Validation failed! {otp_object.validate_attempt} attempts left!"
            )
        )
