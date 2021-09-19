"""Helper methods related to google authentication"""
from typing import Any
from typing import Dict

import requests
from django.conf import settings
from rest_framework.exceptions import ValidationError

GOOGLE_ID_TOKEN_INFO_URL = "https://www.googleapis.com/oauth2/v3/tokeninfo"
GOOGLE_ACCESS_TOKEN_OBTAIN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USER_INFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_AUTHORIZATION_CODE: str = "authorization_code"


def google_get_access_token(*, code: str, redirect_uri: str) -> str:
    """This method get access token from google API"""
    # Reference: https://developers.google.com/identity/protocols/oauth2/web-server#obtainingaccesstokens  # NOQA
    google_client_id: str = settings.GOOGLE_OAUTH2_CLIENT_ID
    google_client_secret: str = settings.GOOGLE_OAUTH2_CLIENT_SECRET
    if not (google_client_id and google_client_secret):
        raise ValueError(
            "GOOGLE_OAUTH2_CLIENT_ID and GOOGLE_OAUTH2_CLIENT_SECRET must be set in your settings file."  # NOQA
        )

    data = {
        "code": code,
        "client_id": google_client_id,
        "client_secret": google_client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": GOOGLE_AUTHORIZATION_CODE,
    }

    response = requests.post(GOOGLE_ACCESS_TOKEN_OBTAIN_URL, data=data)

    if not response.ok:
        raise ValidationError(
            f"Failed to obtain access token from Google. {response.json()}"
        )

    return response.json()["access_token"]


def google_get_user_info(*, access_token: str) -> Dict[str, Any]:
    """This method gives us the user info using google's access token."""
    # Reference: https://developers.google.com/identity/protocols/oauth2/web-server#callinganapi  # NOQA
    response = requests.get(GOOGLE_USER_INFO_URL, params={"access_token": access_token})

    if not response.ok:
        raise ValidationError(
            f"Failed to obtain user info from Google. {response.json()}"
        )

    return response.json()
