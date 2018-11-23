from rest_framework import serializers

from django.utils.text import gettext_lazy as _

from .models import User


class UserSerializer(serializers.ModelSerializer):
    """
    UserRegisterSerializer is a model serializer which includes the
    attributes that are required for registering a user.
    """
    def validate_email(self, value: str):
        """
        If pre-validated email is required, this function checks if
        the email is pre-validated using OTP.
        Parameters
        ----------
        value: str

        Returns
        -------
        value: str

        """

        from . import user_settings

        from .utils import check_validation

        super(UserSerializer, self).validate_email(value)
        if user_settings['EMAIL_VALIDATION']:
            if check_validation(value=value):
                return value
            else:
                raise serializers.ValidationError('The email must be'
                                                  'pre-validated via OTP.')
        else:
            return value

    def validate_mobile(self, value: str):
        """
        If pre-validated mobile number is required, this function
        checks if the mobile is pre-validated using OTP.
        Parameters
        ----------
        value: str

        Returns
        -------
        value: str

        """

        from . import user_settings

        from .utils import check_validation

        if user_settings['MOBILE_VALIDATION']:
            if check_validation(value=value):
                return value
            else:
                raise serializers.ValidationError('The mobile must be'
                                                  'pre-validated via OTP.')
        else:
            return value

    class Meta:
        from .models import User

        model = User
        fields = ('id', 'username', 'name', 'email', 'mobile', 'password',
                  'is_superuser', 'is_staff')
        read_only_fields = ('is_superuser', 'is_staff')
        extra_kwargs = {'password': {'write_only': True}}


class UserShowSerializer(serializers.ModelSerializer):
    """
    UserShowSerializer is a model serializer which shows the attributes
    of a user.
    """

    class Meta:
        from .models import User

        model = User
        fields = ('id', 'username', 'name')
        read_only_fields = ('username', 'name')


class OTPSerializer(serializers.Serializer):
    """
    This Serializer is for sending OTP & verifying destination via otp.
    is_login: Set is_login true if trying to login via OTP.
    """
    email = serializers.EmailField(required=False)
    is_login = serializers.BooleanField(default=False)
    verify_otp = serializers.IntegerField(required=False)
    destination = serializers.CharField(required=True)

    def get_user(self, prop: str, destination: str)->User:
        """
        Provides current user on the basis of property and destination
        provided.
        Parameters
        ----------
        prop: str
            Can be M or E
        destination: str
            Provides value of property
        Returns
        -------
        user: User

        """
        from .models import User

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

        return user

    def validate(self, attrs: dict)->dict:
        """
        Performs custom validation to check if any user exists with
        provided details.
        Parameters
        ----------
        attrs: dict

        Returns
        -------
        attrs: dict

        Raises
        ------
        NotFound: If user is not found
        ValidationError: Email field not provided
        """
        from django.core.validators import EmailValidator, ValidationError

        from rest_framework.exceptions import NotFound

        validator = EmailValidator()
        try:
            validator(attrs['destination'])
        except ValidationError:
            attrs['prop'] = 'M'
        else:
            attrs['prop'] = 'E'

        user = self.get_user(attrs.get('prop'), attrs.get('destination'))

        if not user:
            if attrs['is_login']:
                raise NotFound(_('No user exists with provided details'))
            if ('email' not in attrs.keys()
                    and 'verify_otp' not in attrs.keys()):
                raise serializers.ValidationError(
                    _("email field is compulsory while verifying a"
                      " non-existing user's OTP."))
        else:
            attrs['email'] = user.email
            attrs['user'] = user

        return attrs


class CheckUniqueSerializer(serializers.Serializer):
    """
    This serializer is for checking the uniqueness of
    username/email/mobile of user.
    """
    prop = serializers.ChoiceField(choices=('email', 'mobile', 'username'))
    value = serializers.CharField()
