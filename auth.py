from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model


class MultiFieldModelBackend(ModelBackend):
    """
    This is a ModelBacked that allows authentication with either a username or an email address or mobile number.
    """

    user_model = get_user_model()

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        This function is used to authenticate a user if request, username & password is supplied.
        Parameters
        ----------
        request: HttpRequest
            This is the request that is received by Django view.
        username: str
            This is the username sent by user to the API. The default value is None.
        password: str
            This is the password sent by user to the API. The default value is None.
        kwargs

        Returns
        -------

        """
        import re

        if username is None:
            username = kwargs.get(self.user_model.USERNAME_FIELD)

        if username.isdigit():
            kwargs = {'mobile': username}
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", username):
            kwargs = {'username': username}
        else:
            kwargs = {'email': username}
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
