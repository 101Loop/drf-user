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

``drf-user`` supports Python 3.5 and above.

Prerequisites
-------------

* Add ``drf_user`` and other dependencies in `INSTALLED_APPS` of your projects ``settings.py``

.. code-block:: python

    INSTALLED_APPS = [
        ...
        'drf_user',
        'drfaddons',
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
        'drf_user.auth.MultiFieldModelBackend',
    ]


* Set JWT_AUTH configurations in ``settings.py`` (`these are default values to run drf_user, update as per your requirements`)

.. code-block:: python

    import datetime


    JWT_AUTH = {
        "JWT_ENCODE_HANDLER": "rest_framework_jwt.utils.jwt_encode_handler",
        "JWT_DECODE_HANDLER": "rest_framework_jwt.utils.jwt_decode_handler",
        "JWT_PAYLOAD_HANDLER": "drf_user.auth.jwt_payload_handler",
        "JWT_PAYLOAD_GET_USER_ID_HANDLER": "rest_framework_jwt.utils.jwt_get_user_id_from_payload_handler",
        "JWT_RESPONSE_PAYLOAD_HANDLER": "rest_framework_jwt.utils.jwt_response_payload_handler",
        "JWT_SECRET_KEY": SECRET_KEY,
        "JWT_GET_USER_SECRET_KEY": None,
        "JWT_PUBLIC_KEY": None,
        "JWT_PRIVATE_KEY": None,
        "JWT_ALGORITHM": "HS256",
        "JWT_VERIFY": True,
        "JWT_VERIFY_EXPIRATION": True,
        "JWT_LEEWAY": 0,
        "JWT_EXPIRATION_DELTA": datetime.timedelta(weeks=99999),
        "JWT_AUDIENCE": None,
        "JWT_ISSUER": None,
        "JWT_ALLOW_REFRESH": False,
        "JWT_REFRESH_EXPIRATION_DELTA": datetime.timedelta(days=7),
        "JWT_AUTH_HEADER_PREFIX": "Bearer",
        "JWT_AUTH_COOKIE": None,
    }

* Set `DEFAULT_AUTHENTICATION_CLASSES` in `REST_FRAMEWORK` configuration in your ``settings.py``

.. code-block:: python

    REST_FRAMEWORK = {
        ...
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'drfaddons.auth.JSONWebTokenAuthenticationQS',
            ...
        ),
        ...
    }

* Finally, run ``migrate`` command

.. code-block:: shell

    python manage.py migrate drf_user

Manual Settings
---------------

User can define manual user config in ``settings.py`` file in `USER_SETTINGS` variable. Default options are provided below, update as per your requirements.

.. code-block:: python

    USER_SETTINGS = {
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
