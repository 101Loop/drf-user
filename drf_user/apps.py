from django.apps import AppConfig


class DRFUserConfig(AppConfig):
    name = 'drf_user'
    verbose_name = "Authorization & Authentication"

    def ready(self):
        """
        Register signals
        Call update_user_settings() to update the user setting as per
        django configurations
        Returns
        -------

        Author: Himanshu Shankar (https://himanshus.com)
        """
        from . import update_user_settings
        from .signals.handlers import post_register
        
        update_user_settings()
