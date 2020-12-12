![Build Status](https://github.com/101loop/drf-user/workflows/CI/badge.svg)
[![codecov](https://codecov.io/gh/101Loop/drf-user/branch/master/graph/badge.svg)](https://codecov.io/gh/101Loop/drf-user)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/101Loop/drf-user/master.svg)](https://results.pre-commit.ci/latest/github/101Loop/drf-user/master)
[![Documentation Status](https://readthedocs.org/projects/drf-user/badge/?version=latest)](https://drf-user.readthedocs.io/en/latest/?badge=latest)
[![Documentation Coverage](https://drf-user.readthedocs.io/en/latest/_static/interrogate_badge.svg)](https://github.com/101loop/drf-user)

# Django REST Framework - User

---
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
- [x] Signal based mails
- [x] Mail based activation (optional alternative for OTP based activation)
- [ ] Social Auth Endpoints(Login using fb/google)

# Documentation

---
- For more information on installation and configuration see the documentation
  at: https://drf-user.readthedocs.io/

# Example

---

To get the example project running do:

- Clone this repo
    ```shell
    $ git clone https://github.com/101Loop/drf-user.git
    ```
- Go to `example` folder in newly created directory `drf-user`
    ```shell
    $ cd drf-user/example
    ```
- Create and activate virtual environment.
- Install requirements
    ```shell
    (.venv) $ pip install -r requirements.txt
    ```
- Run testing server:
    ```shell
    (.venv) $ python manage.py runserver
    ```

Take a look at `http://localhost:8000/swagger`. Swagger will list all the APIs of drf-user.

# Contributing

---
- Please file bugs and send pull requests to the
  [GitHub Repository](https://github.com/101loop/drf-user) and
  [Issue Tracker](https://github.com/101loop/drf-user/issues). See
  [CONTRIBUTING.md](https://github.com/101Loop/drf-user/blob/master/CONTRIBUTING.md)
  for details.

* For help and support please reach out to us on
  [Slack](https://101loop.slack.com).
