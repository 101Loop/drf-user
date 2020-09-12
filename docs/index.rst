.. drf-user documentation master file, created by
   sphinx-quickstart on Sat Sep 12 17:26:05 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

====================================
Welcome to drf-user's documentation!
====================================

User APP for Django REST Framework with API Views.


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

|check_| Mobile Number

|check_| Single field for full name

|check_| REST API to register

|check_| REST API to login

|check_| MultiModelBackend: User can login using either of mobile, email or username

|check_| REST API to login with OTP (Same API endpoint as for OTP Verification; Set is_login: true while sending JSON request)

|check_| OTP Verification for mobile and email

|check_| API to register / login with OTP (no pre-registration required)

|check_| Mail sending feature upon successful registration

|check_| SMS sending feature upon successful registration

|check_| Change Password

|check_| Update Profile

|check_| Generic Configuration based on `settings.py`

|uncheck_| Signal based mails: Pending in OTP section

|uncheck_| Mail based activation (optional alternative for OTP based activation)

|uncheck_| Social Auth Endpoints(Login using fb/google)

========
Contents
========

.. toctree::
   :maxdepth: 3

   installation


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
