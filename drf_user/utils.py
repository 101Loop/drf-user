"""Collection of general helper functions."""
import datetime

import pytz
from django.http import HttpRequest
from django.utils import timezone
from django.utils.text import gettext_lazy as _
from drfaddons.utils import get_client_ip
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

user_settings = update_user_settings()
otp_settings = user_settings["OTP"]


def datetime_passed_now(source):
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


def check_unique(prop, value):
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


def generate_otp(prop, value):
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
    random_number = User.objects.make_random_password(
        length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
    )

    # Checks if random number is unique among non-validated OTPs and
    # creates new until it is unique.
    while OTPValidation.objects.filter(otp__exact=random_number).filter(
        is_validated=False
    ):
        random_number = User.objects.make_random_password(
            length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
        )

    # Get or Create new instance of Model with value of provided value
    # and set proper counter.
    try:
        otp_object = OTPValidation.objects.get(destination=value)
    except OTPValidation.DoesNotExist:
        otp_object = OTPValidation()
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


def send_otp(value, otpobj, recip):
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
    otp = otpobj.otp

    if not datetime_passed_now(otpobj.reactive_at):
        raise PermissionDenied(
            detail=_("OTP sending not allowed until: " + str(otpobj.reactive_at))
        )

    message = (
        "OTP for verifying "
        + otpobj.get_prop_display()
        + ": "
        + value
        + " is "
        + otp
        + ". Don't share this with anyone!"
    )

    try:
        rdata = send_message(message, otp_settings["SUBJECT"], [value], [recip])
    except ValueError as err:
        raise APIException(_("Server configuration error occured: %s") % str(err))

    otpobj.reactive_at = timezone.now() + datetime.timedelta(
        minutes=otp_settings["COOLING_PERIOD"]
    )
    otpobj.save()

    return rdata


def login_user(user: User, request: HttpRequest) -> dict:
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
    token = RefreshToken.for_user(user)

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


def check_validation(value):
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
        otp_object = OTPValidation.objects.get(destination=value)
        return otp_object.is_validated
    except OTPValidation.DoesNotExist:
        return False


def validate_otp(value, otp):
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
        otp_object = OTPValidation.objects.get(destination=value, is_validated=False)

        # Decrement validate_attempt
        otp_object.validate_attempt -= 1

        if str(otp_object.otp) == str(otp):
            otp_object.is_validated = True
            otp_object.save()
            return True

        elif otp_object.validate_attempt <= 0:
            generate_otp(otp_object.prop, value)
            raise AuthenticationFailed(
                detail=_("Incorrect OTP. Attempt exceeded! OTP has been " "reset.")
            )

        else:
            otp_object.save()
            raise AuthenticationFailed(
                detail=_(
                    "OTP Validation failed! "
                    + str(otp_object.validate_attempt)
                    + " attempts left!"
                )
            )

    except OTPValidation.DoesNotExist:
        raise NotFound(
            detail=_(
                "No pending OTP validation request found for provided "
                "destination. Kindly send an OTP first"
            )
        )
