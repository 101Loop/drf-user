from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    """
    UserRegisterSerializer is a model serializer which includes the attributes that are required for registering a user.
    """
    def validate_email(self, value):
        from . import user_settings

        from .utils import check_validation

        super(UserSerializer, self).validate_email(value)
        if user_settings['EMAIL_VALIDATION']:
            if check_validation(value=value):
                return value
            else:
                raise serializers.ValidationError('The email must be pre-validated via OTP.')
        else:
            return value

    def validate_mobile(self, value):
        from . import user_settings

        from .utils import check_validation

        if user_settings['MOBILE_VALIDATION']:
            if check_validation(value=value):
                return value
            else:
                raise serializers.ValidationError('The mobile must be pre-validated via OTP.')
        else:
            return value

    class Meta:
        from .models import User

        model = User
        fields = ('id', 'username', 'name', 'email', 'mobile', 'password', 'is_superuser', 'is_staff')
        read_only_fields = ('is_superuser', 'is_staff')
        extra_kwargs = {'password': {'write_only': True}}


class UserShowSerializer(serializers.ModelSerializer):
    """
    UserShowSerializer is a model serializer which shows the attributes of a user.
    """

    class Meta:
        from .models import User

        model = User
        fields = ('id', 'username', 'name')
        read_only_fields = ('username', 'name')


class SendOTPSerializer(serializers.ModelSerializer):
    """
    This Serializer is for sending OTP & verifying destination via otp.
    """
    email = serializers.EmailField(required=True)
    otp = serializers.IntegerField(required=False)
    prop = serializers.CharField(source='get_prop_display')

    def validate(self, data):
        from django.utils.text import gettext_lazy as _

        from drfaddons.add_ons import validate_mobile

        if data['prop'] == 'E':
            from django.core.validators import EmailValidator, ValidationError

            validator = EmailValidator()
            try:
                validator(data['destination'])
            except ValidationError:
                raise serializers.ValidationError(_('Provided destination is not an Email address.'))
        else:
            if not validate_mobile(data['destination']):
                raise serializers.ValidationError(_('Provided destination is not a Mobile Number.'))
        return data

    class Meta:
        from .models import OTPValidation

        model = OTPValidation
        fields = ('prop', 'destination')


class LoginOTPSerializer(serializers.Serializer):
    """
    Serializer of Login using OTP.
    """
    destination = serializers.CharField(required=True)
    otp = serializers.IntegerField(required=False)
    prop = serializers.CharField(required=False)

    def validate(self, attrs):
        from django.core.validators import EmailValidator, ValidationError

        validator = EmailValidator()

        try:
            validator(attrs['username'])
        except ValidationError:
            attrs['prop'] = 'M'
        else:
            attrs['prop'] = 'E'


class CheckUniqueSerializer(serializers.Serializer):
    """
    This serializer is for checking the uniqueness of username/email/mobile of user.
    """
    prop = serializers.ChoiceField(choices=('email', 'mobile', 'username'))
    value = serializers.CharField()
