"""Tests for drf_user/utils.py module"""
import datetime

import pytest
from django.http import HttpRequest
from django.test import TestCase
from django.utils import timezone
from model_bakery import baker
from rest_framework.exceptions import AuthenticationFailed

from drf_user import utils as utils
from drf_user.models import OTPValidation
from drf_user.models import User
from drf_user.utils import get_client_ip


class TestCheckUnique(TestCase):
    """check_unique test"""

    def setUp(self) -> None:
        """Create user object using model_bakery"""
        self.user = baker.make(
            "drf_user.User",
            email="user@email.com",
        )

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if User object created or not"""
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_check_non_unique(self):
        """Check if the user is non-unique"""
        self.assertTrue(utils.check_unique("email", "user1@email.com"))

    @pytest.mark.django_db
    def test_check_unique(self):
        """Check if the user is unique"""
        self.assertFalse(utils.check_unique("email", "user@email.com"))


class TestCheckValidation(TestCase):
    """check_validation test"""

    def setUp(self) -> None:
        """Create OTPValidation object using model_bakery"""
        self.validated_otp_validation = baker.make(
            "drf_user.OTPValidation", destination="user@email.com", is_validated=True
        )

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if OTPValidation object is created or not"""
        self.assertEqual(1, OTPValidation.objects.count())

    @pytest.mark.django_db
    def test_check_validated_object(self):
        """Check if the value is validated"""
        self.assertTrue(utils.check_validation("user@email.com"))

    @pytest.mark.django_db
    def test_check_non_validated_object(self):
        """Check if the value is not validated"""
        self.assertFalse(utils.check_validation("user1@email.com"))


class TestGenerateOTP(TestCase):
    """generate_otp Test"""

    @pytest.mark.django_db
    def test_generate_otp(self):
        """Check generate_otp successfully generates OTPValidation object or not"""
        utils.generate_otp("email", "user1@email.com")
        self.assertEqual(1, OTPValidation.objects.count())

    @pytest.mark.django_db
    def test_generate_otp_reactive_past(self):
        """
        Check generate_otp generates a new otp if the reactive time is yet to be over
        """
        otp_validation1 = utils.generate_otp("email", "user1@email.com")
        otp_validation2 = utils.generate_otp("email", "user1@email.com")
        self.assertNotEqual(otp_validation1.otp, otp_validation2.otp)

    @pytest.mark.django_db
    def test_generate_otp_reactive_future(self):
        """
        Check generate_otp returns the same otp if the reactive time is already over
        """
        otp_validation1 = utils.generate_otp("email", "user1@email.com")

        """
        Simulating that the reactive time is already been over 5 minutes ago
        """
        otp_validation1.reactive_at = timezone.now() + datetime.timedelta(minutes=5)
        otp_validation1.save()

        otp_validation2 = utils.generate_otp("email", "user1@email.com")
        self.assertEqual(otp_validation2.otp, otp_validation1.otp)


class TestValidateOTP(TestCase):
    """validate_otp test"""

    def setUp(self) -> None:
        """Create OTPValidation object using model_bakery"""
        self.otp_validation = baker.make(
            "drf_user.OTPValidation", destination="user@email.com", otp=12345
        )

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if OTPValidation object is created or not"""
        self.assertEqual(1, OTPValidation.objects.count())

    @pytest.mark.django_db
    def test_validate_otp(self):
        """Check if OTPValidation object is created or not"""
        self.assertTrue(utils.validate_otp("user@email.com", 12345))

    @pytest.mark.django_db
    def test_validate_otp_raises_attempt_exceeded_exception(self):
        """Check function raises attempt exceeded exception"""

        """
        Set the validate_attempt to 0. Raises attempt exceeded exception
        """
        self.otp_validation.validate_attempt = 0
        self.otp_validation.save()

        with self.assertRaises(AuthenticationFailed) as context_manager:
            utils.validate_otp("user@email.com", 56123)

        self.assertEqual(
            "Incorrect OTP. Attempt exceeded! OTP has been reset.",
            str(context_manager.exception.detail),
        )

    @pytest.mark.django_db
    def test_validate_otp_raises_invalid_otp_exception(self):
        """Check function raises attempt exceeded exception"""
        with self.assertRaises(AuthenticationFailed) as context_manager:
            utils.validate_otp("user@email.com", 5623)

        self.assertEqual(
            "OTP Validation failed! 2 attempts left!",
            str(context_manager.exception.detail),
        )


class TestGetClientIP(TestCase):
    """get_client_ip test"""

    def test_meta_none(self):
        """Check get_client_ip returns None when META is empty"""
        request = HttpRequest()
        request.META = {}
        ip = get_client_ip(request)
        self.assertIsNone(ip)

    def test_meta_single_with_http_x_forwarded_for(self):
        """Check get_client_ip returns first item from HTTP_X_FORWARDED_FOR"""
        request = HttpRequest()
        request.META = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
        }
        result = get_client_ip(request)
        self.assertEqual(result, "177.139.233.139")

    def test_meta_single_with_remote_addr(self):
        """Check get_client_ip returns first item from HTTP_X_FORWARDED_FOR"""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "198.84.193.158",
        }
        result = get_client_ip(request)
        self.assertEqual(result, "198.84.193.158")

    def test_meta_multi(self):
        """
        Check get_client_ip returns ip from HTTP_X_FORWARDED_FOR when
        HTTP_X_FORWARDED_FOR and REMOTE_ADDR is present
        """
        request = HttpRequest()
        request.META = {
            "HTTP_X_FORWARDED_FOR": "177.139.233.139, 198.84.193.157, 198.84.193.158",
            "REMOTE_ADDR": "177.139.233.133",
        }
        result = get_client_ip(request)
        self.assertEqual(result, "177.139.233.139")
