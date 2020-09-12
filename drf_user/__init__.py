__title__ = "User - Django REST Framework"
__version__ = "0.0.8"
__author__ = "101Loop"
__license__ = "GPLv3"

default_app_config = "drf_user.apps.DRFUserConfig"

user_settings = {
    "DEFAULT_ACTIVE_STATE": False,
    "OTP": {
        "LENGTH": 5,
        "ALLOWED_CHARS": "1234567890",
        "VALIDATION_ATTEMPTS": 3,
        "SUBJECT": "OTP for Verification",
        "COOLING_PERIOD": 3,
    },
    "MOBILE_VALIDATION": True,
    "EMAIL_VALIDATION": True,
    "REGISTRATION": {
        "SEND_MAIL": False,
        "SEND_MESSAGE": False,
        "MAIL_SUBJECT": "Welcome to DRF-USER",
        "SMS_BODY": "Your account has been created",
        "TEXT_MAIL_BODY": "Your account has been created.",
        "HTML_MAIL_BODY": "Your account has been created.",
    },
}


def update_user_settings() -> dict:
    """
    Updates user setting from django default setting

    TODO: Think of a better way, using Signal preferably.

    Returns
    -------
    user_settings: dict

    Author: Himanshu Shankar (https://himanshus.com)
    """
    from django.conf import settings

    custom_settings = getattr(settings, "USER_SETTINGS", None)

    if custom_settings:
        if isinstance(custom_settings, dict):
            for key, value in custom_settings.items():
                if key not in ["OTP", "REGISTRATION"]:
                    user_settings[key] = value
                elif key == "OTP":
                    if isinstance(value, dict):
                        for otp_key, otp_value in value.items():
                            user_settings["OTP"][otp_key] = otp_value
                    else:
                        raise TypeError("USER_SETTING attribute OTP must be a" " dict.")
                elif key == "REGISTRATION":
                    if isinstance(value, dict):
                        for reg_key, reg_value in value.items():
                            user_settings["REGISTRATION"][reg_key] = reg_value
                    else:
                        raise TypeError(
                            "USER_SETTING attribute REGISTRATION" " must be a dict."
                        )
        else:
            raise TypeError("USER_SETTING must be a dict.")

        if user_settings["REGISTRATION"]["SEND_MAIL"]:
            if not getattr(settings, "EMAIL_HOST", None):
                raise ValueError(
                    "EMAIL_HOST must be defined in django setting" " for sending mail."
                )
            if not getattr(settings, "EMAIL_FROM", None):
                raise ValueError(
                    "EMAIL_FROM must be defined in django setting"
                    " for sending mail. Who is sending email?"
                )

    return user_settings
