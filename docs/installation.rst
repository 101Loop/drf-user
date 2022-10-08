============
Installation
============

Each of the following steps needs to be configured for the `drf-user` to be fully functional.

Getting the code
----------------

Install from PyPI (recommended) with ``pip``::

    pip install drf_user

Or Install via ``easy_install``::

    easy_install drf_user

Or Install from ``source code``::

    pip install -e git+https://github.com/101Loop/drf-user#egg=drf_user

Requirements
------------

``drf-user`` supports Python 3.7 and above.

Prerequisites
-------------

* Add ``drf_user`` and other dependencies in `INSTALLED_APPS` of your projects ``settings.py``

.. code-block:: python

    INSTALLED_APPS = [
        ...
        'drf_user',
        'rest_framework',
        'django_filters',
        ...
    ]

* Include urls of `drf_user` in your projects ``urls.py``

.. code-block:: python

    from django.urls import path

    urlpatterns = [
        ...
        path('api/user/', include('drf_user.urls')),
        ...
    ]

Or if you have `regex` based urls use `re_path`

.. code-block:: python

    from django.urls import re_path

    urlpatterns = [
        ...
        re_path(r'^api/user/', include('drf_user.urls')),
        ...
    ]

* Include `AUTH_USER_MODEL` in ``settings.py``

.. code-block:: python

    ...
    AUTH_USER_MODEL = 'drf_user.User'
    ...

* Set `AUTHENTICATION_BACKEND` in ``settings.py``

.. code-block:: python

    AUTHENTICATION_BACKENDS = [
        'drf_user.auth.MultiFieldModelBackend', # to support login with email/mobile
    ]

* Set `DEFAULT_AUTHENTICATION_CLASSES` in `REST_FRAMEWORK` configuration in your ``settings.py``

.. code-block:: python

    REST_FRAMEWORK = {
        ...
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'rest_framework_simplejwt.authentication.JWTAuthentication',
            ...
        ),
        ...
    }


* Set `SIMPLE_JWT` configurations in ``settings.py`` (`these are default values from Simple JWT, update as per your requirements`)

.. code-block:: python

    from datetime import timedelta

    ...

    # see https://django-rest-framework-simplejwt.readthedocs.io/en/latest/settings.html
    SIMPLE_JWT = {
        "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
        "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
        "ROTATE_REFRESH_TOKENS": False,
        "BLACKLIST_AFTER_ROTATION": True,
        "UPDATE_LAST_LOGIN": True,
        "ALGORITHM": "HS256",
        "SIGNING_KEY": SECRET_KEY,
        "VERIFYING_KEY": None,
        "AUDIENCE": None,
        "ISSUER": None,
        "AUTH_HEADER_TYPES": ("Bearer",),
        "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
        "USER_ID_FIELD": "id",
        "USER_ID_CLAIM": "user_id",
        "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
        "TOKEN_TYPE_CLAIM": "token_type",
        "JTI_CLAIM": "jti",
        "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
        "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
        "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),
    }


* Finally, run ``migrate`` command

.. code-block:: shell

    python manage.py migrate drf_user

Manual Settings
---------------

User can define manual user config in ``settings.py`` file in `USER_SETTINGS` variable. Default options are provided below, update as per your requirements.

.. code-block:: python

    USER_SETTINGS = {
        "MOBILE_OPTIONAL": True,
        'DEFAULT_ACTIVE_STATE': False,
        'OTP': {
            'LENGTH': 7,
            'ALLOWED_CHARS': '1234567890',
            'VALIDATION_ATTEMPTS': 3,
            'SUBJECT': 'OTP for Verification',
            'COOLING_PERIOD': 3
        },
        'MOBILE_VALIDATION': True,
        'EMAIL_VALIDATION': True,
        'REGISTRATION': {
            'SEND_MAIL': False,
            'SEND_MESSAGE': False,
            'MAIL_SUBJECT': 'Welcome to DRF-USER',
            'SMS_BODY': 'Your account has been created',
            'TEXT_MAIL_BODY': 'Your account has been created.',
            'HTML_MAIL_BODY': 'Your account has been created.'
        }
    }
