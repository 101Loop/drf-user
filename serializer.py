from rest_framework import serializers
from .models import User


class UserRegisterSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('username', 'name', 'email', 'mobile', 'password')


class UserShowSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('username', 'name')
        read_only_fields = ('username', 'name')


class SendOTPSerializer(serializers.Serializer):
    """
    This Serializer is for sending OTP.
    """
    value = serializers.CharField()
    prop = serializers.ChoiceField(choices=('email', 'mobile'))
    email = serializers.EmailField()


class OTPVerify(serializers.Serializer):
    value = serializers.CharField()
    otp = serializers.CharField(default=None)


class CheckUniqueSerializer(serializers.Serializer):
    prop = serializers.ChoiceField(choices=('email', 'mobile', 'username'))
    value = serializers.CharField()
