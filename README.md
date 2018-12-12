# Django REST Framework - User

**User APP for Django REST Framework with API Views.**<br>

`DRF User` is a Django app that overrides default user app to provide additional attributes and functionalities. The
current stable version includes:
- [x] Mobile Number
- [x] Single field for full name
- [x] REST API to register
- [x] REST API to login
- [x] MultiModelBackend: User can login using either of mobile, email or username
- [x] REST API to login with OTP (Same API endpoint as for OTP Verification; Set `is_login: true` while sending JSON
request)
- [x] OTP Verification for mobile and email
- [x] Mail sending feature upon successful registration
- [x] SMS sending feature upon successful registration
- [x] Change Password
- [x] Update Profile
- [x] settings.py based configuration
- [ ] Signal based mails: Pending in OTP section
- [ ] Mail based activation (optional alternative for OTP based activation)

#### Contributors

- **[Civil Machines Technologies Private Limited](https://github.com/civilmahines)**: For providing me platform and 
funds for research work. This project is hosted currently with `CMT` only. 
- [Himanshu Shankar](https://github.com/iamhssingh): The app was initiated and worked upon majorly by Himanshu. This app
is currently in use in various other django projects that are developed by him.
- [Aditya Gupta](https://github.com/ag93999): Aditya has updated view in the app to include additional features such as
Change Password. He is also an active contributor in this repository and is working to replace `ValidateAndPerformView`
with appropriate `Django REST Framework GenericAPI Views`.

** We're looking for someone who can contribute on docs part **

#### Installation

- Download and Install via `pip`
```
pip install drf_user
```
or

Download and Install via `easy_install`
```
easy_install drf_user
```
- Add `drf_user` in `INSTALLED_APPS`<br>
```
INSTALLED_APPS = [
    ...
    'drf_user',
    ...
]
```
- Also add other dependencies in `INSTALLED_APPS`<br>
```
INSTALLED_APPS = [
    ...
    'drfaddons',
    'rest_framework',
    'django_filters',
    ...
]
```
- Include urls of `drf_user` in `urls.py`
```
urlpatterns = [
    ...
    path('api/user/', include('drf_user.urls')),
    ...
]

# or

urlpatterns = [
    ...
    url(r'^api/user/', include('drf_user.urls')),
    ...
]
```
- Include AUTH_USER_MODEL in settings.py
```
...
AUTH_USER_MODEL = 'drf_user.User'
...
``` 
- Finally, run `migrate` command
```
python manage.py migrate drf_user
```

### Additional settings
These additional settings are **required** to use `drf_user` at its full extent.
These settings should be done in `settings.py`

- Set `AUTHENTICATION_BACKEND`:
```
AUTHENTICATION_BACKENDS = [
    'drf_user.auth.MultiFieldModelBackend',
]
```

- Set `JWT_PAYLOAD_HANDLER` in `JWT_AUTH` configurations
```
JWT_AUTH = {
    ...
    'JWT_PAYLOAD_HANDLER': 'drf_user.auth.jwt_payload_handler',
    ...
}
```

- Set `DEFAULT_AUTHENTICATION_CLASSES` in `REST_FRAMEWORK` configuration
```
REST_FRAMEWORK = {
    ...
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'drfaddons.auth.JSONWebTokenAuthentication',
        ...
    ),
}
```

#### Manual Settings

User can define manual setting in `settings.py` file in `USER_SETTINGS` variable . Default options are provided below

```
user_settings = {
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
```
