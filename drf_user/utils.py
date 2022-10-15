"""Collection of general helper functions."""
import datetime
import logging
import re
from typing import Dict, Optional

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.http import HttpRequest
from django.utils import timezone
from django.utils.text import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, NotFound, PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.utils import datetime_from_epoch
from sendsms import api

from drf_user import update_user_settings
from drf_user.models import AuthTransaction, OTPValidation, User

user_settings: dict = update_user_settings()
otp_settings: dict = user_settings["OTP"]

logger = logging.getLogger(__name__)


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
    settings. Checks source is in future or in the past. False if it's in future.
    Parameters
    ----------
    source: datetime object than may or may not be naive

    Returns
    -------
    bool

    Author: Himanshu Shankar (https://himanshus.com)
    """
    if source.tzinfo is not None and source.tzinfo.utcoffset(source) is not None:
        return source <= datetime.datetime.now(datetime.timezone.utc)

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


def generate_otp(*, destination_property: str, destination: str) -> OTPValidation:
    """
    This function generates an OTP and saves it into Model. It also
    sets various counters, such as send_counter,
    is_validated, validate_attempt.
    Parameters
    ----------
    destination_property: str
        This specifies the type for which OTP is being created. Can be::
            E
            M
    destination: str
        This specifies the value for which OTP is being created.

    Returns
    -------
    otp_object: OTPValidation
        This is the instance of OTP that is created.
    Examples
    --------
    To create an OTP for an Email test@testing.com
    >>> print(generate_otp('E', 'test@testing.com'))
    OTPValidation object

    >>> print(generate_otp('E', 'test@testing.com').otp)
    5039164
    """
    # Create a random number
    random_number: str = User.objects.make_random_password(
        length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
    )

    # Checks if random number is unique among non-validated OTPs and
    # creates new until it is unique.
    while OTPValidation.objects.filter(otp__exact=random_number).filter(is_validated=False):
        random_number: str = User.objects.make_random_password(
            length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
        )

    # Get or Create new instance of Model with value of provided value
    # and set proper counter.
    try:
        otp_object: OTPValidation = OTPValidation.objects.get(destination=destination)
    except OTPValidation.DoesNotExist:
        otp_object: OTPValidation = OTPValidation()
        otp_object.destination = destination
    else:
        if not datetime_passed_now(otp_object.reactive_at):
            return otp_object

    otp_object.otp = random_number
    otp_object.prop = destination_property

    # Set is_validated to False
    otp_object.is_validated = False

    # Set attempt counter to OTP_VALIDATION_ATTEMPTS, user has to enter
    # correct OTP in 3 chances.
    otp_object.validate_attempt = otp_settings["VALIDATION_ATTEMPTS"]

    otp_object.reactive_at = timezone.now() - datetime.timedelta(minutes=1)
    otp_object.save()
    return otp_object


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


def validate_mobile(mobile: str) -> bool:
    """
    This function checks if the mobile number is valid or not.
    Parameters
    ----------
    mobile: str
        This is the mobile number to be checked.

    Returns
    -------
    bool
        True if mobile number is valid, False otherwise.
    Examples
    --------
    To check if '9999999999' is a valid mobile number
    >>> print(validate_mobile('9999999999'))
    True
    """
    match = re.match(r"^[6-9]\d{9}$", str(mobile))
    if match is None:
        raise ValidationError("Invalid Mobile Number")
    return True


def validate_otp(*, destination: str, otp_val: int) -> bool:
    """
    This function is used to validate the OTP for a particular value.
    It also reduces the attempt count by 1 and resets OTP.
    Parameters
    ----------
    destination: str
        This is the unique entry for which OTP has to be validated.
    otp_val: int
        This is the OTP that will be validated against one in Database.

    Returns
    -------
    bool: True, if OTP is validated
    """

    try:
        # Try to get OTP Object from Model and initialize data dictionary
        otp_object: OTPValidation = OTPValidation.objects.get(
            destination=destination, is_validated=False
        )
    except OTPValidation.DoesNotExist as e:
        raise NotFound(
            detail=_(
                "No pending OTP validation request found for provided destination."
                " Kindly send an OTP first"
            )
        ) from e

    # Decrement validate_attempt
    otp_object.validate_attempt -= 1

    if str(otp_object.otp) == str(otp_val):
        # match otp
        otp_object.is_validated = True
        otp_object.save(update_fields=["is_validated", "validate_attempt"])
        return True

    elif otp_object.validate_attempt <= 0:
        # check if attempts exceeded and regenerate otp and raise error
        generate_otp(destination_property=otp_object.prop, destination=destination)
        raise AuthenticationFailed(detail=_("Incorrect OTP. Attempt exceeded! OTP has been reset."))

    else:
        # update attempts and raise error
        otp_object.save(update_fields=["validate_attempt"])
        raise AuthenticationFailed(
            detail=_(f"OTP Validation failed! {otp_object.validate_attempt} attempts left!")
        )


def send_message(
    message: str,
    subject: str,
    recip_email: str,
    recip_mobile: Optional[str] = None,
    html_message: Optional[str] = None,
) -> Dict:
    """
    Sends message to specified value.

    Parameters
    ----------
    message: str
        Message that is to be sent to user.
    subject: str
        Subject that is to be sent to user, in case prop is an email.
    recip_mobile: str
        Recipient Mobile Number to whom message is being sent.
    recip_email: str
        Recipient to whom EMail is being sent.
    html_message: str
        HTML variant of message, if any.

    Returns
    -------
    sent: dict
    """
    sent = {"success": False, "message": None, "mobile_message": None}

    if not getattr(settings, "EMAIL_HOST", None):
        raise ValueError("EMAIL_HOST must be defined in django setting for sending mail.")
    if not getattr(settings, "EMAIL_FROM", None):
        raise ValueError(
            "EMAIL_FROM must be defined in django setting "
            "for sending mail. Who is sending email?"
        )

    # check if email is valid
    validate_email(recip_email)

    if recip_mobile:
        # check for valid mobile numbers
        validate_mobile(recip_mobile)

    try:
        send_mail(
            subject=subject,
            message=message,
            html_message=html_message,
            from_email=settings.EMAIL_FROM,
            recipient_list=[recip_email],
        )
    except Exception as e:  # noqa
        sent["message"] = f"Email Message sending failed! {str(e.args)}"
        sent["success"] = False
    else:
        sent["message"] = "Email Message sent successfully!"
        sent["success"] = True

    if recip_mobile:
        try:
            api.send_sms(body=message, to=recip_mobile, from_phone=None)
        except Exception as e:  # noqa
            logger.debug("Message sending failed", exc_info=e)
            sent["mobile_message"] = f"Mobile Message sending failed! {str(e.args)}"
        else:
            sent["mobile_message"] = "Mobile Message sent successfully!"

    return sent


def send_otp(
    *, otp_obj: OTPValidation, recip_email: str, recip_mobile: Optional[str] = None
) -> Dict:
    """
    This function sends OTP to specified value.
    Parameters
    ----------
    otp_obj: OTPValidation
        OTPValidation object that contains the OTP and other details.
    recip_email: str
        Recipient to whom EMail is being sent.
    recip_mobile: Optional[str]
        Recipient Mobile Number to whom message is being sent.

    Returns
    -------
    data: dict
        Dictionary containing the status of the OTP sent.
    """
    otp_val: str = otp_obj.otp

    if not datetime_passed_now(otp_obj.reactive_at):
        raise PermissionDenied(f"OTP sending not allowed until: {otp_obj.reactive_at}")

    message: str = (
        f"OTP for verifying {otp_obj.get_prop_display()}: {otp_obj.destination} is {otp_val}."
        f" Don't share this with anyone!"
    )

    try:
        data: dict = send_message(message, otp_settings["SUBJECT"], recip_email, recip_mobile)
    except (ValueError, ValidationError) as e:
        raise serializers.ValidationError({"detail": f"OTP sending failed! because {e}"}) from e

    otp_obj.reactive_at = timezone.now() + datetime.timedelta(
        minutes=otp_settings["COOLING_PERIOD"]
    )
    otp_obj.save(update_fields=["reactive_at"])

    return data
