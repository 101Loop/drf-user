"""Tests for drf_user/utils.py module"""
import pytest
from django.test import TestCase
from model_bakery import baker

from drf_user import utils as utils
from drf_user.models import OTPValidation
from drf_user.models import User


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
        self.assertEqual(User.objects.count(), 1)

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
        self.assertEqual(OTPValidation.objects.count(), 1)

    @pytest.mark.django_db
    def test_check_validated_object(self):
        """Check if the value is validated"""
        self.assertTrue(utils.check_validation("user@email.com"))

    @pytest.mark.django_db
    def test_check_non_validated_object(self):
        """Check if the value is not validated"""
        self.assertFalse(utils.check_validation("user1@email.com"))
