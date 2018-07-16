# Django REST Framework - User

**User APP for Django REST Framework with API Views.**<br>

`DRF User` is a Django app that overrides default user app to provide additional attributes and functionalities. The
current stable version includes:
- [x] Mobile Number
- [x] Single field for full name
- [x] REST API to register
- [x] REST API to login
- [x] MultiModelBackend: User can login using either of mobile, email or username
- [x] REST API to login with OTP
- [x] OTP Verification for mobile and email
- [x] Mail sending feature upon successful registration

Following features are being worked upon:
- [ ] Change Password
- [ ] Update Profile

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
or<br>
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
- Include urls of `drf_user` in `urls.py`
```
urlpatterns = [
    ...
    path('/api/user/', include('drf_user.urls')),
    ...
]

# or

urlpatterns = [
    ...
    url(r'api/user/', include('drf_user.urls')),
    ...
]
```

- Finally, run `migrate` command
```
python manage.py migrate drf_user
```

#### Manual Settings

User can define manual setting in `settings.py` file in `USER_SETTINGS` variable . Default options are provided below

```
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
        'MAIL_SUBJECT': 'Welcome to DRF-USER',
        'TEXT_MAIL_BODY': 'Your account has been created.',
        'HTML_MAIL_BODY': 'Your account has been created.'
    }
}
```
