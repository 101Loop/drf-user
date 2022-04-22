"""
With these settings, tests run faster.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INSTALLED_APPS = (
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "drf_user",
    "drfaddons",
    "rest_framework",
    "django_filters",
)

# GENERAL
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#secret-key
SECRET_KEY = "dummy"

# https://docs.djangoproject.com/en/dev/ref/settings/#test-runner
TEST_RUNNER = "django.test.runner.DiscoverRunner"

TIME_ZONE = "Asia/Kolkata"
# CACHES
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#caches
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "",
    }
}

# PASSWORDS
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#password-hashers
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# EMAIL
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#email-backend
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
EMAIL_FROM = "test"
# URL
# ------------------------------------------------------------------------------
ROOT_URLCONF = "drf_user.urls"

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/
STATIC_URL = "/static/"

STATIC_ROOT = os.path.join(BASE_DIR, "static/")

MEDIA_URL = "/media/"

MEDIA_ROOT = os.path.join(BASE_DIR, "media/")

# DATABASE
# ------------------------------------------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

AUTHENTICATION_BACKENDS = ["drf_user.auth.MultiFieldModelBackend"]

AUTH_USER_MODEL = "drf_user.User"

USER_SETTINGS = {
    "MOBILE_OPTIONAL": True,
    "DEFAULT_ACTIVE_STATE": False,
    "OTP": {
        "LENGTH": 7,
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
