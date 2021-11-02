"""
All static variables used in the system.
"""
from typing import List
from typing import Tuple

EMAIL: str = "E"
MOBILE: str = "M"
DESTINATION_CHOICES: List[Tuple[str, str]] = [
    (EMAIL, "EMail Address"),
    (MOBILE, "Mobile Number"),
]

GOOGLE_ID_TOKEN_INFO_URL: str = "https://www.googleapis.com/oauth2/v3/tokeninfo"
GOOGLE_ACCESS_TOKEN_OBTAIN_URL: str = "https://oauth2.googleapis.com/token"
GOOGLE_USER_INFO_URL: str = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_AUTHORIZATION_CODE: str = "authorization_code"
