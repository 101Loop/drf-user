=================
API Documentation
=================

Register
--------

API Docs for Register.

.. http:post:: /register/

    Register a new user to the system.

    .. code-block:: json

        {
            "username": "username",
            "name": "name",
            "email": "email@user.com",
            "mobile": "9999999999",
            "password": "password"
        }

    :jsonparam str username: unique username
    :jsonparam str name: name of the user
    :jsonparam str email: unique email of user
    :jsonparam str mobile: unique mobile number of user
    :jsonparam str password: password of user

    :statuscode 201: if supplied params are valid
    :statuscode 400: if supplied params are invalid

Login
-----

API Docs for Login.

.. http:post:: /login/

    Login a user to the system.

    .. code-block:: json

        {
            "username": "username",
            "password": "my_secret_password",
        }

    :jsonparam str username: unique username
    :jsonparam str password: password of user

    :statuscode 200: if supplied params are valid
    :statuscode 422: if supplied params are invalid

Account
-------

API Docs for Account.

.. http:get:: /account/

    Get a user.

    .. code-block:: json

        {
            "id": 1,
            "username": "dummy_username",
            "name": "dummy_name",
            "email": "email@dummy.com",
            "mobile": "9999999999",
            "is_superuser": true,
            "is_staff": true
        }

    :statuscode 200: if request is authenticated
    :statuscode 403: if request is not authenticated

|

.. http:put:: /account/

    Update all details of user.

    .. code-block:: json

        {
            "username": "updated_username",
            "name": "updated_name",
            "email": "email@updated.com",
            "mobile": "9999999999",
            "password": "updated_password"
        }

    :jsonparam str username: unique username
    :jsonparam str name: name of the user
    :jsonparam str email: unique email of user
    :jsonparam str mobile: unique mobile number of user
    :jsonparam str password: password of user

    :statuscode 200: if request is authenticated
    :statuscode 400: if any param is not supplied
    :statuscode 403: if request is not authenticated

|

.. http:patch:: /account/

    Update some details of user.

    .. code-block:: json

        {
            "name": "partial_updated_name",
            "email": "email@partial_updated.com",
        }

    :jsonparam str username: unique username, optional
    :jsonparam str name: name of the user, optional
    :jsonparam str email: unique email of user, optional
    :jsonparam str mobile: unique mobile number of user, optional
    :jsonparam str password: password of user, optional

    :statuscode 200: if request is authenticated
    :statuscode 400: if any param is not supplied
    :statuscode 403: if request is not authenticated

OTP
---

API Docs for OTP.

.. http:post:: /otp/

    Generate, validate and login using OTP.

    .. code-block:: json

        {
            "destination": "1234567890",
            "email": "email@django.com",
            "verify_otp": "123456",
            "is_login": "True",
            "_comment1": "destination can be email/mobile",
            "_comment2": "when using mobile as destination, use email",
            "_comment3": "to verify otp, add verify_otp to request",
            "_comment4": "for log in, just add is_login to request",
        }

    :jsonparam str destination: destination where otp to be sent
    :jsonparam str email: if mobile is used in destination then use this for email, optional
    :jsonparam str verify_otp: to verify otp, optional
    :jsonparam str is_login: to login user, optional

    :statuscode 201: if supplied params are valid
    :statuscode 400: if supplied params are invalid
    :statuscode 403: if supplied otp is invalid

OTP Register Login
------------------

API Docs for OTP Register Login.

.. http:post:: /otpreglogin/

    Register, Login using OTP.

    .. code-block:: json

        {
            "name": "some_awesome_name",
            "email": "email@django.com",
            "mobile": "1234567890",
            "verify_otp": "123456",
        }

    :jsonparam str name: name of user
    :jsonparam str email: email of user
    :jsonparam str mobile: mobile of user
    :jsonparam str verify_otp: to verify otp, optional

    :statuscode 201: if supplied params are valid
    :statuscode 400: if supplied params are invalid
    :statuscode 403: if supplied otp is invalid

Password
--------

API Docs for Reset Password.

.. http:post:: /password/reset/

    Reset user's password.

    * To reset user's password, first you have to call `/otp/` with `is_login` parameter value false.
    * Then call this API

    .. code-block:: json

        {
            "email": "email@django.com",
            "otp": "123456",
            "password": "my_new_secret_password",
        }

    :jsonparam str email: email of user
    :jsonparam str otp: otp received on email
    :jsonparam str password: new password

    :statuscode 202: if supplied params are valid
    :statuscode 400: if supplied params are invalid
    :statuscode 403: if supplied otp is invalid

Is Unique
---------

API Docs for Is Unique.

.. http:post:: /isunique/

    Check uniqueness of username, email, mobile.

    .. code-block:: json

        {
            "prop": "email",
            "value": "email@django.com"
        }

    :jsonparam str prop: property to check for uniqueness, choices are username, email, mobile
    :jsonparam str value: value to check for uniqueness

    :statuscode 200: if supplied params are valid
    :statuscode 400: if supplied params are invalid
