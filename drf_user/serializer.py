from rest_framework import serializers
from .models import User


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    UserRegisterSerializer is a model serializer which includes the attributes that are required for registering a user.

    Returns
    -------
     tuple
        Returns a tuple containing::
                data = dict
                    This is a dictionary containing::
                        'username' : str
                            This contains the username of the user.
                        'name' : str
                            This contains the name of the user.
                        'email' : str
                            This contains the email of the user.
                        'mobile' : str
                            This contains the mobile number of the user.
                        'password' : str
                            This contains the password of the user.
                        'organization' : str
                            This contains the organisation of the user.
    Examples
    --------
    >>> print(UserRegisterSerializer(data={'username':'test@testing.com', 'name':'test', 'email': 'test@testing.com', 'mobile' : '123456', 'password': '123780', 'organization': 'CMT'}))
    UserRegisterSerializer(data={'username': 'test@testing.com', 'name': 'dinesh', 'email': 'test@testing.com', 'mobile': '123456', 'password': '123780', 'organization': 'CMT'}):
    username = CharField(label='Unique UserName', max_length=254, validators=[<UniqueValidator(queryset=User.objects.all())>])
    name = CharField(label='Full Name', max_length=500)
    email = EmailField(label='EMail Address', max_length=254, validators=[<UniqueValidator(queryset=User.objects.all())>])
    mobile = CharField(label='Mobile Number', max_length=150, validators=[<UniqueValidator(queryset=User.objects.all())>])
    password = CharField(max_length=128)
    organization = CharField(max_length=500)
    """

    class Meta:
        model = User
        fields = ('username', 'name', 'email', 'mobile', 'password')


class UserShowSerializer(serializers.ModelSerializer):
    """
    UserShowSerializer is a model serializer which shows the attributes of a user.

    Returns
    -------
     tuple
        Returns a tuple containing::
                data = dict
                    This is a dictionary containing::
                        'username' : str
                        'name' : str
    Examples
    --------
    >>> print(UserShowSerializer(data = {'username':'test@testing.com', 'name':'test'}))
    UserShowSerializer(data={'username': 'test@testing.com', 'name': 'test'}):
    username = CharField(label='Unique UserName', read_only=True)
    name = CharField(label='Full Name', read_only=True)
    """

    class Meta:
        model = User
        fields = ('username', 'name')
        read_only_fields = ('username', 'name')


class SendOTPSerializer(serializers.Serializer):
    """
    This Serializer is for sending OTP.

    Returns
    -------
     tuple
        Returns a tuple containing::
                data = dict
                    This is a dictionary containing::
                        'value' : str
                            This is the value at which and for which OTP is to be sent.
                        'prop' : str
                            This is the type of value. It can be "email" or "mobile"
                        'email' : str
    Examples
    --------
    >>> print(SendOTPSerializer(data = {'value': 'value', 'prop': '123345', 'email':'test@testing.com'}))
    SendOTPSerializer(data={'value': 'value', 'prop': '123345, 'email': 'test@testing.com'}):
    value = CharField()
    prop = ChoiceField(choices=('email', 'mobile'))
    email = EmailField()
    """
    value = serializers.CharField()
    prop = serializers.ChoiceField(choices=('email', 'mobile'))
    email = serializers.EmailField()


class OTPVerify(serializers.Serializer):
    """
    This serializer is for verifying OTP.

    Returns
    -------
     tuple
        Returns a tuple containing::
                data = dict
                    This is a dictionary containing::
                        'value' : str
                        'otp' : str
    Examples
    --------
    >>> print(OTPVerify(data = {'value':'value', 'otp':'6518631'}))
    OTPVerify(data={'value': 'value', 'otp': '6518631'}):
    value = CharField()
    otp = CharField(default=None)
    """
    value = serializers.CharField()
    otp = serializers.CharField(default=None)


class CheckUniqueSerializer(serializers.Serializer):
    """
    This serializer is for checking the uniqueness of username/email/mobile of user.

    Returns
    -------
     tuple
        Returns a tuple containing::
                data = dict
                    This is a dictionary containing::
                        'prop' : str
                            This is the type of value. It can be "email" or "mobile"
                        'value' : str
                            This is the value at which and for which OTP is to be sent.
    Examples
    --------
    >>> print(CheckUniqueSerializer(data={'prop':'12344', 'value': 'value'}))
    CheckUniqueSerializer(data={'prop': '12344', 'value': 'value'}):
    prop = ChoiceField(choices=('email', 'mobile', 'username'))
    value = CharField()
    """
    prop = serializers.ChoiceField(choices=('email', 'mobile', 'username'))
    value = serializers.CharField()


class ForgotPasswordSerializer(serializers.Serializer):
    """
    This serializer is for letting the user to change the password after being successfully LoggedIn.
    """
    new_password = serializers.CharField(max_length=16, required=True)


class UpdateProfileSerializer(serializers.ModelSerializer):
    """
    This model serializer is to update the profile of a user.
    """

    email = serializers.EmailField(required=False)
    mobile = serializers.CharField(required=False)
    name = serializers.CharField(required=False)
    organization = serializers.CharField(required=False)

    class Meta:

        from .models import User

        model = User
        fields = ('name', 'email', 'mobile', 'organization')

