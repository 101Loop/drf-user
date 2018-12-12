from . import update_user_settings
from .models import User

from django.utils.text import gettext_lazy as _

user_settings = update_user_settings()
otp_settings = user_settings['OTP']


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
    user = User.objects.extra(where=[prop + ' = \'' + value + '\''])
    if user.count() is not 0:
        return False
    else:
        return True


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
    from .models import OTPValidation

    import datetime

    # Create a random number
    random_number = User.objects.make_random_password(
        length=otp_settings['LENGTH'],
        allowed_chars=otp_settings['ALLOWED_CHARS'])

    # Checks if random number is unique among non-validated OTPs and
    # creates new until it is unique.
    while OTPValidation.objects.filter(otp__exact=random_number).filter(
            is_validated=False):
        random_number = User.objects.make_random_password(
            length=otp_settings['LENGTH'],
            allowed_chars=otp_settings['ALLOWED_CHARS'])

    # Get or Create new instance of Model with value of provided value
    # and set proper counter.
    otp_object, created = OTPValidation.objects.get_or_create(
        destination=value)
    if not created:
        if otp_object.reactive_at > datetime.datetime.now():
            return otp_object

    otp_object.otp = random_number
    otp_object.prop = prop

    # Set is_validated to False
    otp_object.is_validated = False

    # Set attempt counter to OTP_VALIDATION_ATTEMPS, user has to enter
    # correct OTP in 3 chances.
    otp_object.validate_attempt = otp_settings['VALIDATION_ATTEMPTS']

    otp_object.reactive_at = (datetime.datetime.now() -
                              datetime.timedelta(minutes=1))
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

    from drfaddons.utils import send_message

    from rest_framework.exceptions import PermissionDenied

    import datetime

    otp = otpobj.otp

    if otpobj.reactive_at > datetime.datetime.now():
        raise PermissionDenied(
            detail=_('OTP sending not allowed until: '
                     + otpobj.reactive_at.strftime('%d-%h-%Y %H:%M:%S')))

    message = ("OTP for verifying " + otpobj.get_prop_display() + ": "
               + value + " is " + otp + ". Don't share this with anyone!")

    rdata = send_message(message, otp_settings['SUBJECT'], [value], [recip])

    otpobj.reactive_at = datetime.datetime.now() + datetime.timedelta(
        minutes=otp_settings['COOLING_PERIOD'])
    otpobj.save()

    return rdata


def login_user(user: User, request)->(dict, int):
    """
    This function is used to login a user. It saves the authentication in
    AuthTransaction model.
    Parameters
    ----------
    user: django.contrib.auth.get_user_model
    request: HttpRequest

    Returns
    -------
    tuple:
        data: dict
        status_code: int
    """
    from drfaddons.utils import get_client_ip

    from rest_framework_jwt.utils import jwt_encode_handler

    from .models import AuthTransaction
    from .auth import jwt_payload_handler

    import datetime

    token = jwt_encode_handler(jwt_payload_handler(user))
    user.last_login = datetime.datetime.now()
    user.save()
    AuthTransaction(created_by=user, ip_address=get_client_ip(request),
                    token=token,
                    session=user.get_session_auth_hash()).save()

    data = {'session': user.get_session_auth_hash(), 'token': token}
    return data


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
    from .models import OTPValidation

    try:
        otp_object = OTPValidation.objects.get(destination=value)
        if otp_object.is_validated:
            return True
        else:
            return False
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
    from .models import OTPValidation

    from rest_framework.exceptions import AuthenticationFailed, NotFound

    try:
        # Try to get OTP Object from Model and initialize data dictionary
        otp_object = OTPValidation.objects.get(destination=value,
                                               is_validated=False)

        # Decrement validate_attempt
        otp_object.validate_attempt -= 1

        if str(otp_object.otp) == str(otp):
            otp_object.is_validated = True
            otp_object.save()
            return True

        elif otp_object.validate_attempt <= 0:
            generate_otp(otp_object.prop, value)
            raise AuthenticationFailed(
                detail=_('Incorrect OTP. Attempt exceeded! OTP has been '
                         'reset.'))

        else:
            otp_object.save()
            raise AuthenticationFailed(
                detail=_('OTP Validation failed! ' + str(
                    otp_object.validate_attempt) + ' attempts left!'))

    except OTPValidation.DoesNotExist:
        raise NotFound(
            detail=_('No pending OTP validation request found for provided'
                     'destination. Kindly send an OTP first'))
