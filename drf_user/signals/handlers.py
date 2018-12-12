from django.db.models.signals import post_save
from django.dispatch import receiver

from django.contrib.auth import get_user_model

from drf_user.models import OTPValidation


@receiver(post_save, sender=get_user_model())
def post_register(sender, instance: get_user_model(), created, **kwargs):
    from drf_user import user_settings

    from drfaddons.utils import send_message

    if created:
        if user_settings['REGISTRATION']['SEND_MAIL']:
            send_message(
                message=user_settings['REGISTRATION']['TEXT_MAIL_BODY'],
                subject=user_settings['REGISTRATION']['MAIL_SUBJECT'],
                recip=[instance.email], recip_email=[instance.email],
                html_message=user_settings['REGISTRATION']['HTML_MAIL_BODY'])
        if user_settings['REGISTRATION']['SEND_MESSAGE']:
            send_message(
                message=user_settings['REGISTRATION']['SMS_BODY'],
                subject=user_settings['REGISTRATION']['MAIL_SUBJECT'],
                recip=[instance.mobile], recip_email=[instance.mobile])
