"""
Custom backends to facilitate authorizations

Author: Himanshu Shankar (https://himanshus.com)
"""
import re

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class MultiFieldModelBackend(ModelBackend):
    """
    This is a ModelBacked that allows authentication with either a
    username or an email address or mobile number.
    """

    user_model = get_user_model()

    def authenticate(self, request, username=None, password=None, **kwargs) -> None:
        """
        This function is used to authenticate a user. User can send
        either of email, mobile or username in request to
        authenticate. The function will check accordingly and login the
        user.
        Parameters
        ----------
        request: HttpRequest
            This is the request that is received by Django view.
        username: str
            This is the username sent by user to the API. The default
            value is None.
        password: str
            This is the password sent by user to the API. The default
            value is None.
        kwargs

        Returns
        -------
        user: django.contrib.auth.get_user_model
        or
        None
        """
        if username is None:
            username = kwargs.get(self.user_model.USERNAME_FIELD)

        if username.isdigit():
            kwargs = {"mobile": username}
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", username):
            kwargs = {"username": username}
        else:
            kwargs = {"email": username}
        try:
            user = self.user_model.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except self.user_model.DoesNotExist:
            return None

    def get_user(self, username: int) -> None:
        """Returns user object if exists otherwise None

        Parameters
        ----------
        username: int
            ID of the user will be passed here.
        Returns
        -------
        user: django.contrib.auth.get_user_model
        or
        None

        """

        try:
            return self.user_model.objects.get(pk=username)
        except self.user_model.DoesNotExist:
            return None
