"""Helper Mixins"""
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated


class AuthAPIMixin:
    """Mixin for Authenticated APIs"""

    permission_classes = (IsAuthenticated,)


class PublicAPIMixin:
    """Mixin for Public APIs"""

    authentication_classes = ()
    permission_classes = (AllowAny,)
