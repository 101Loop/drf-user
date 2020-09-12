![Build Status](https://github.com/101loop/drf-user/workflows/CI/badge.svg)
[![codecov](https://codecov.io/gh/101Loop/drf-user/branch/master/graph/badge.svg)](https://codecov.io/gh/101Loop/drf-user)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Documentation Status](https://readthedocs.org/projects/drf-user/badge/?version=latest)](https://drf-user.readthedocs.io/en/latest/?badge=latest)
[![Documentation Coverage](https://drf-user.readthedocs.io/en/latest/_static/interrogate_badge.svg)](https://github.com/101loop/drf-user)

# Django REST Framework - User

**User APP for Django REST Framework with API Views.**<br>

`DRF User` is a Django app that overrides default user app to provide additional
attributes and functionalities. The current stable version includes:

- [x] Mobile Number
- [x] Single field for full name
- [x] REST API to register
- [x] REST API to login
- [x] MultiModelBackend: User can login using either of mobile, email or
      username
- [x] REST API to login with OTP (Same API endpoint as for OTP Verification; Set
      `is_login: true` while sending JSON request)
- [x] OTP Verification for mobile and email
- [x] API to register / login with OTP (no pre-registration required)
- [x] Mail sending feature upon successful registration
- [x] SMS sending feature upon successful registration
- [x] Change Password
- [x] Update Profile
- [x] Generic Configuration based on settings.py
- [ ] Signal based mails: Pending in OTP section
- [ ] Mail based activation (optional alternative for OTP based activation)
- [ ] Social Auth Endpoints(Login using fb/google)

# Documentation

For more information on installation and configuration see the documentation at:
https://drf-user.readthedocs.io/

# Contributing

Please file bugs and send pull requests to the
[GitHub repository](https://github.com/101loop/drf-user) and
[issue tracker](https://github.com/101loop/drf-user/issues). See
[CONTRIBUTING.md](https://github.com/101Loop/drf-user/blob/master/CONTRIBUTING.md)
for details.
