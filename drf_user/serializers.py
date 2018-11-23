from rest_framework import serializers

from django.utils.text import gettext_lazy as _


class UserSerializer(serializers.ModelSerializer):
    """
    UserRegisterSerializer is a model serializer which includes the
    attributes that are required for registering a user.
    """
    def validate_email(self, value):
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

    def validate_mobile(self, value):
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
    UserShowSerializer is a model serializer which shows the attributes of a
    user.
    """

    class Meta:
        from .models import User

        model = User
        fields = ('id', 'username', 'name')
        read_only_fields = ('username', 'name')


class OTPSerializer(serializers.Serializer):
    """
    This Serializer is for sending OTP & verifying destination via otp.
    """
    email = serializers.EmailField(required=False)
    is_login = serializers.BooleanField(default=False)
    verify_otp = serializers.IntegerField(required=False)
    destination = serializers.CharField(required=True)

    def get_user(self, prop, destination):
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

    def validate(self, attrs):
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
