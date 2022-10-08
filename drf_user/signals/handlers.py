"""Config for django signals"""
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

User = get_user_model()


@receiver(post_save, sender=User)
def post_register(sender, instance: User, created: bool, **kwargs):
    """Sends mail/message to users after registeration

    Parameters
    ----------
    sender: get_user_model()

    instance: get_user_model()

    created: bool
    """

    from drf_user import user_settings

    from drf_user.utils import send_message

    if created:
        if user_settings["REGISTRATION"]["SEND_MAIL"]:
            send_message(
                message=user_settings["REGISTRATION"]["TEXT_MAIL_BODY"],
                subject=user_settings["REGISTRATION"]["MAIL_SUBJECT"],
                recip_email=instance.email,
                html_message=user_settings["REGISTRATION"]["HTML_MAIL_BODY"],
            )
        if user_settings["REGISTRATION"]["SEND_MESSAGE"]:
            send_message(
                message=user_settings["REGISTRATION"]["SMS_BODY"],
                subject=user_settings["REGISTRATION"]["MAIL_SUBJECT"],
                recip_email=instance.email,
                recip_mobile=instance.mobile,
            )
