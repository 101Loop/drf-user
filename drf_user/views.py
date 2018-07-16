from rest_framework.mixins import status
from drfaddons.views import ValidateAndPerformView
from django.contrib.auth import get_user_model
from . import user_settings, update_user_settings
from rest_framework.generics import UpdateAPIView


update_user_settings()
User = get_user_model()
otp_settings = user_settings['OTP']


def check_unique(prop, value):
    """
    This function checks if the value provided is present in Database or can be created in DBMS as unique data.
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
    To check if test@testing.com email address is already present in Database
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
    This function generates an OTP and saves it into Model. It also sets various counters, such as send_counter,
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
    random_number = User.objects.make_random_password(length=otp_settings['LENGTH'],
                                                      allowed_chars=otp_settings['ALLOWED_CHARS'])

    # Checks if random number is unique among non-validated OTPs and creates new until it is unique.
    while OTPValidation.objects.filter(otp__exact=random_number).filter(is_validated=False):
        random_number = User.objects.make_random_password(length=otp_settings['LENGTH'],
                                                          allowed_chars=otp_settings['ALLOWED_CHARS'])

    # Get or Create new instance of Model with value of provided value and set proper counter.
    otp_object, created = OTPValidation.objects.get_or_create(destination=value)
    if not created:
        if otp_object.reactive_at > datetime.datetime.now():
            return otp_object

    otp_object.otp = random_number
    otp_object.type = prop

    # Set is_validated to False
    otp_object.is_validated = False

    # Set attempt counter to OTP_VALIDATION_ATTEMPS, user has to enter correct OTP in 3 chances.
    otp_object.validate_attempt = otp_settings['VALIDATION_ATTEMPTS']

    otp_object.reactive_at = datetime.datetime.now() - datetime.timedelta(minutes=1)
    otp_object.save()
    return otp_object


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
    tuple
        Returns a tuple containing::
                data: dict
                    This is a dictionary containing::
                        'success': bool
                            This will be True if OTP is validated, else False
                        'OTP': str
                            This will contain a proper message about the OTP Validation
                status: int
                    This will be a HTTP Status Code with resepect to the type of success or error occurred.
    Examples
    --------
    To validate an OTP against test@testing.com with wrong OTP
    >>> print(validate_otp('test@testing.com', 6518631))
    ({'OTP': 'OTP Validation failed! 2 attempts left!', 'success': False}, 401)

    To validate an OTP against random@email.com with value that doesn't exist
    >>>print(validate_otp('random@email.com', 6518631))
    ({'OTP': 'Provided value to verify not found!', 'success': False}, 404)

    To validate a correct OTP with value test@testing.com
    >>>print(validate_otp('test@testing.com', 5039164))
    ({'OTP': 'OTP Validated successfully!', 'success': True}, 202)

    To validate incorrect OTP more than 3 times or re-validate already validated value with incorrect OTP
    >>>print(validate_otp('test@testing.com', 6518631))
    ({'OTP': 'Attempt exceeded! OTP has been reset!', 'success': False}, 401)
    """
    from .models import OTPValidation

    # Initialize data dictionary that will be returned
    data = {'success': False}

    try:
        # Try to get OTP Object from Model and initialize data dictionary
        otp_object = OTPValidation.objects.get(destination=value)

        # Decrement validate_attempt
        otp_object.validate_attempt -= 1

        if str(otp_object.otp) == str(otp):
            otp_object.is_validated = True
            otp_object.save()
            data['OTP'] = 'OTP Validated successfully!'
            data['success'] = True
            status_code = status.HTTP_202_ACCEPTED
        elif otp_object.validate_attempt <= 0:
            generate_otp(otp_object.type, value)
            status_code = status.HTTP_401_UNAUTHORIZED
            data['OTP'] = 'Attempt exceeded! OTP has been reset!'
        else:
            otp_object.save()
            data['OTP'] = 'OTP Validation failed! ' + str(otp_object.validate_attempt) + ' attempts left!'
            status_code = status.HTTP_401_UNAUTHORIZED
    except OTPValidation.DoesNotExist:
        # If OTP object doesn't exist set proper message and status_code
        data['OTP'] = 'Provided value to verify not found!'
        status_code = status.HTTP_404_NOT_FOUND

    return data, status_code


def send_otp(prop, value, otpobj, recip):
    """
    This function sends OTP to specified value.
    Parameters
    ----------
    prop: str
        This is the type of value. It can be "email" or "mobile"
    value: str
        This is the value at which and for which OTP is to be sent.
    otpobj: OTPValidation
        This is the OTP or One Time Passcode that is to be sent to user.
    recip: str
        This is the recipient to whom EMail is being sent. This will be deprecated once SMS feature is brought in.

    Returns
    -------

    """
    from drfaddons.add_ons import send_message

    import datetime

    otp = otpobj.otp
    rdata = {'success': False, 'message': None}

    if otpobj.reactive_at > datetime.datetime.now():
        rdata['message'] = 'OTP sending not allowed until: ' + otpobj.reactive_at.strftime('%d-%h-%Y %H:%M:%S')
        return rdata

    message = "OTP for verifying " + prop + ": " + value + " is " + otp + ". Don't share this with anyone!"

    rdata = send_message(prop, message, otp_settings['SUBJECT'], recip)

    otpobj.reactive_at = datetime.datetime.now() + datetime.timedelta(minutes=otp_settings['COOLING_PERIOD'])
    otpobj.save()

    return rdata


def login_user(user: User, request)->(dict, int):
    """
    This function is used to login a user. It saves the authentication in AuthTransaction model.
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
    from drfaddons.add_ons import get_client_ip
    from drfaddons.auth import jwt_payload_handler

    from rest_framework_jwt.utils import jwt_encode_handler

    from .models import AuthTransaction

    import datetime

    token = jwt_encode_handler(jwt_payload_handler(user))
    user.last_login = datetime.datetime.now()
    user.save()
    AuthTransaction(user=user, ip_address=get_client_ip(request), token=token, session=user.get_session_auth_hash())\
        .save()

    data = {'session': user.get_session_auth_hash(), 'token': token}
    status_code = status.HTTP_200_OK
    return data, status_code


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


class Register(ValidateAndPerformView):
    """
    This Registers a new User to the system.
    The email address and mobile number to be used to register must be pre-validated with OTP.
    """
    from .serializer import UserRegisterSerializer

    serializer_class = UserRegisterSerializer

    def validated(self, serialized_data, *args, **kwargs):
        from drfaddons.add_ons import send_message

        if user_settings['EMAIL_VALIDATION']:
            email_validated = check_validation(serialized_data.initial_data['email'])
        else:
            email_validated = True

        if user_settings['MOBILE_VALIDATION']:
            mobile_validated = check_validation(serialized_data.initial_data['email'])
        else:
            mobile_validated = True

        data = dict()

        if email_validated and mobile_validated:
            user = User.objects.create_user(username=serialized_data.initial_data['username'],
                                            email=serialized_data.initial_data['email'],
                                            name=serialized_data.initial_data['name'],
                                            password=serialized_data.initial_data['password'],
                                            mobile=serialized_data.initial_data['mobile'])

            data = {'name': user.get_full_name(), 'username': user.get_username(), 'id': user.id, 'email': user.email,
                    'mobile': user.mobile}

            status_code = status.HTTP_201_CREATED
            if user_settings['REGISTRATION']['SEND_MAIL']:
                send_message('EMAIL', user_settings['REGISTRATION']['TEXT_MAIL_BODY'],
                             user_settings['REGISTRATION']['MAIL_SUBJECT'], user.email)
        else:
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            if not email_validated:
                data['email'] = ['Provided EMail is not validated!']
            if not mobile_validated:
                data['mobile'] = ['Provided Mobile is not validated!']

        return data, status_code


class Login(ValidateAndPerformView):
    """
    This is used to Login into system. The data required are 'username' and 'password'.
    In 'username' user can provide either username or mobile or email address.
    """
    from rest_framework_jwt.serializers import JSONWebTokenSerializer

    serializer_class = JSONWebTokenSerializer

    def validated(self, serialized_data, **kwargs):
        from django.contrib.auth import authenticate

        user = authenticate(username=serialized_data.initial_data['username'],
                            password=serialized_data.initial_data['password'])

        if user is not None:
            data, status_code = login_user(user, kwargs.get('request'))

        else:
            data = {'message': "User not found/Password combination wrong"}
            status_code = status.HTTP_401_UNAUTHORIZED

        return data, status_code


class SendOTP(ValidateAndPerformView):
    """
    This sends an OTP to a value. This process should be followed by VerifyOTP to validate an email or mobile.
    'prop': Can be email or mobile
    'value': A valid email address or mobile number
    'email': Temporarily here. OTP will be sent here in case of mobile.
    """
    from .serializer import SendOTPSerializer

    serializer_class = SendOTPSerializer

    def validated(self, serialized_data, *args, **kwargs):
        from drfaddons.add_ons import validate_email, validate_mobile

        prop = serialized_data.initial_data['prop']
        value = serialized_data.initial_data['value']
        if prop is 'email' and not validate_email(value):
            status_code = status.HTTP_400_BAD_REQUEST
            data = {'value': ['Given value is not an EMail ID!']}

        elif prop is 'mobile' and not validate_mobile(value):
            status_code = status.HTTP_400_BAD_REQUEST
            data = {'value': ['Given value is not Mobile Number!']}

        else:
            if check_unique(prop, value):
                data = {'unique': True}
                otpobj = generate_otp(prop, value)

                sentotp = send_otp(prop, value, otpobj, serialized_data.initial_data['email'])

                data['OTP'] = sentotp['message']
                if sentotp['success']:
                    otpobj.send_counter += 1
                    otpobj.save()
                    status_code = status.HTTP_201_CREATED
                else:
                    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            else:
                data = {'unique': False}
                status_code = status.HTTP_409_CONFLICT
        return data, status_code


class VerifyOTP(ValidateAndPerformView):
    """
    This verifies an OTP against a value (email address or mobile). This process should be done before registering a
    user with any email or mobile.
    'value': A valid email address or mobile number which is to be validated.
    'otp': The OTP sent at your email address.
    """
    from .serializer import OTPVerify

    serializer_class = OTPVerify

    def validated(self, serialized_data, *args, **kwargs):
        return validate_otp(serialized_data.data['value'], serialized_data.data['otp'])


class CheckUnique(ValidateAndPerformView):
    """
    This view checks if the given property -> value pair is unique (or doesn't exists yet)
    'prop': A property to check for uniqueness (username/email/mobile)
    'value': Value against property which is to be checked for.
    """
    from .serializer import CheckUniqueSerializer

    serializer_class = CheckUniqueSerializer

    def validated(self, serialized_data, *args, **kwargs):
        return {'unique': check_unique(serialized_data.initial_data['prop'], serialized_data.initial_data['value'])},\
               status.HTTP_200_OK


class LoginOTP(ValidateAndPerformView):
    from .serializer import OTPVerify

    serializer_class = OTPVerify

    def validated(self, serialized_data, *args, **kwargs):
        otp = serialized_data.data['otp']
        value = serialized_data.data['value']

        if value.isdigit():
            prop = 'mobile'
            try:
                user = User.objects.get(mobile=value)
            except User.DoesNotExist:
                user = None
        else:
            prop = 'email'
            try:
                user = User.objects.get(email=value)
            except User.DoesNotExist:
                user = None

        if user is None:
            data = {'success': False, 'message': 'No user exists with provided details!'}
            status_code = status.HTTP_404_NOT_FOUND

        else:
            if otp is None:
                otp_obj = generate_otp(prop, value)
                data = send_otp(prop, value, otp_obj, user.email)

                if data['success']:
                    status_code = status.HTTP_201_CREATED
                else:
                    status_code = status.HTTP_400_BAD_REQUEST

            else:
                data, status_code = validate_otp(value, int(otp))
                if status_code == status.HTTP_202_ACCEPTED:
                    data, status_code = login_user(user, self.request)

        return data, status_code


class ChangePassword(UpdateAPIView):
    """
    This view will let the user to change the password.
    """

    from .serializer import ForgotPasswordSerializer
    from .models import User

    queryset = User.objects.all()
    serializer_class = ForgotPasswordSerializer

    def update(self, request, *args, **kwargs):

        from drfaddons.add_ons import JsonResponse

        sdata = self.ForgotPasswordSerializer(data=request.data)
        if sdata.is_valid():
            request.user.set_password(sdata.data['new_password'])
            request.user.save()
            return JsonResponse({'success': True}, status=status.HTTP_202_ACCEPTED)
        else:
            return JsonResponse(sdata.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileView(UpdateAPIView):
    """
    This view is to update a user profile.
    """
    from .serializer import UpdateProfileSerializer
    from .models import User

    queryset = User.objects.all()
    serializer_class = UpdateProfileSerializer

    def update(self, request, *args, **kwargs):

        from drfaddons.add_ons import JsonResponse

        serializer = self.UpdateProfileSerializer(request.user, data=request.data)
        if serializer.is_valid():
            self.perform_update(serializer)
            request.user.save()
            return JsonResponse(serializer.data, status=status.HTTP_202_ACCEPTED)
        else:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
