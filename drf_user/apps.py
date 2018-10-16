from django.apps import AppConfig


class DRFUserConfig(AppConfig):
    name = 'drf_user'
    verbose_name = "Authorization & Authentication"

    def ready(self):
        from . import update_user_settings
        from .signals.handlers import post_register
        
        update_user_settings()
