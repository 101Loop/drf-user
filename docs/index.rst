.. drf-user documentation master file, created by
   sphinx-quickstart on Sat Sep 12 17:26:05 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

====================================
Welcome to drf-user's documentation!
====================================

.. image:: https://readthedocs.org/projects/drf-instamojo/badge/?version=latest
   :target: https://drf-bulk.readthedocs.io/en/latest/
   :alt: Documentation Status
.. image:: https://github.com/101loop/drf-user/workflows/CI/badge.svg
   :target: https://github.com/101loop/drf-user
   :alt: CI
.. image:: https://codecov.io/gh/101Loop/drf-user/branch/master/graph/badge.svg?token=e0AVdjOABf
   :target: https://codecov.io/gh/101Loop/drf-user
.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
   :target: https://github.com/psf/black
   :alt: Code style: black

User APP for Django REST Framework with API Views.


.. note::

   One of the winners of `PyCharm Project of the Decade Competition <(https://www.jetbrains.com/lp/pycharm-10-years/>`__


========
Overview
========

``Django REST Framework - User``  is a Django app that overrides default user app to provide additional attributes and functionalities.


.. |check_| raw:: html

    <input checked=""  disabled="" type="checkbox">

.. |uncheck_| raw:: html

    <input disabled="" type="checkbox">


============
Feature List
============

|check_| JWT Support (Using `Simple JWT <https://django-rest-framework-simplejwt.readthedocs.io/>`__)

|check_| Mobile Number

|check_| Single field for full name

|check_| REST API to register

|check_| REST API to login

|check_| MultiModelBackend: User can login using either of mobile, email or username

|check_| REST API to login with OTP (Same API endpoint as for OTP Verification; Set is_login: true while sending JSON request)

|check_| OTP Verification for mobile and email

|check_| API to register / login with OTP (no pre-registration required)

|check_| API to set user's profile image

|check_| Mail sending feature upon successful registration

|check_| SMS sending feature upon successful registration

|check_| Change Password

|check_| Update Profile

|check_| Generic Configuration based on `settings.py`

|check_| Signal based mails: Pending in OTP section

|check_| Mail based activation (optional alternative for OTP based activation)

|uncheck_| Social Auth Endpoints(Login using fb/google)

========
Contents
========

.. toctree::
   :maxdepth: 3

   installation

.. toctree::
   :maxdepth: 3

   api-doc

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
