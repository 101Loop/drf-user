"""

Author: Himanshu Shankar (https://himanshus.com)
"""
from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    """
    UserManager class for Custom User Model

    Author: Himanshu Shankar (https://himanshus.com)
    Source: Can't find link but the following solution is inspired
    from a solution provided on internet.
    """

    use_in_migrations = True

    def _create_user(self, username, email, password, fullname, mobile, **extra_fields):
        """
        Creates and saves a User with the given email and password

        Author: Himanshu Shankar (https://himanshus.com)
        """
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)
        user = self.model(
            username=username, email=email, name=fullname, mobile=mobile, **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email, password, name, mobile, **extra_fields):
        """
        Creates a normal user considering the specified user settings
        from Django Project's settings.py
        Parameters
        ----------
        username: str
        email: str
        password: str
        name: str
        mobile: str
        extra_fields: dict

        Returns
        -------
        User Instance
        Author: Himanshu Shankar (https://himanshus.com)
        """

        from . import update_user_settings

        vals = update_user_settings()

        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_active", vals.get("DEFAULT_ACTIVE_STATE", False))

        return self._create_user(
            username, email, password, name, mobile, **extra_fields
        )

    def create_superuser(self, username, email, password, name, mobile, **extra_fields):
        """
        Creates a super user considering the specified user settings
        from Django Project's settings.py
        Parameters
        ----------
        username: str
        email: str
        password: str
        name: str
        mobile: str
        extra_fields: dict

        Returns
        -------
        User Instance

        Author: Himanshu Shankar (https://himanshus.com)
        """
        from . import update_user_settings

        vals = update_user_settings()

        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_active", vals.get("DEFAULT_ACTIVE_STATE", False))

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        return self._create_user(
            username, email, password, name, mobile, **extra_fields
        )
