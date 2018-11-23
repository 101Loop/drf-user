from django.db.models.signals import post_save
from django.dispatch import receiver

from django.contrib.auth import get_user_model

from drf_user.models import OTPValidation


@receiver(post_save, sender=get_user_model())
def post_register(sender, instance, created, **kwargs):
    from drf_user import user_settings

    from drfaddons.add_ons import send_message

    if created:
        if user_settings['REGISTRATION']['SEND_MAIL']:
            send_message(
                message=user_settings['REGISTRATION']['TEXT_MAIL_BODY'],
                subject=user_settings['REGISTRATION']['MAIL_SUBJECT'],
                recip=[instance.email], recip_email=[instance.email])
