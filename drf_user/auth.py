"""
Custom backends to facilitate authorizations

Author: Himanshu Shankar (https://himanshus.com)
"""
from django.contrib.auth.backends import ModelBackend


class MultiFieldModelBackend(ModelBackend):
    """
    This is a ModelBacked that allows authentication with either a
    username or an email address or mobile number.
    """

    from django.contrib.auth import get_user_model

    user_model = get_user_model()

    def authenticate(self, request, username=None, password=None, **kwargs):
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
        import re

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

    def get_user(self, username):
        try:
            return self.user_model.objects.get(pk=username)
        except self.user_model.DoesNotExist:
            return None


def jwt_payload_handler(user):
    """
    A custom JWT Payload Handler that adds certain extra data in
    payload such as: email, mobile, name

    Source: Himanshu Shankar (https://github.com/iamhssingh)
    Parameters
    ----------
    user: get_user_model()

    Returns
    -------
    payload: dict
    """
    import uuid

    from calendar import timegm
    from datetime import datetime

    from rest_framework_jwt.compat import get_username
    from rest_framework_jwt.compat import get_username_field
    from rest_framework_jwt.settings import api_settings

    username_field = get_username_field()
    username = get_username(user)

    payload = {
        "user_id": user.pk,
        "is_admin": user.is_staff,
        "exp": datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
    }

    if hasattr(user, "email"):
        payload["email"] = user.email

    if hasattr(user, "mobile"):
        payload["mobile"] = user.mobile

    if hasattr(user, "name"):
        payload["name"] = user.name

    if isinstance(user.pk, uuid.UUID):
        payload["user_id"] = str(user.pk)

    payload[username_field] = username

    # Include original issued at time for a brand new token,
    # to allow token refresh

    if api_settings.JWT_ALLOW_REFRESH:
        payload["orig_iat"] = timegm(datetime.utcnow().utctimetuple())

    if api_settings.JWT_AUDIENCE is not None:
        payload["aud"] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload["iss"] = api_settings.JWT_ISSUER

    return payload
