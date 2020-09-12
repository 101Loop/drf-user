"""Tests for drf_user/models.py module"""
import pytest
from django.test import TestCase
from model_bakery import baker

from drf_user.models import AuthTransaction
from drf_user.models import OTPValidation
from drf_user.models import User


class TestUserModel(TestCase):
    """User Model"""

    def setUp(self) -> None:
        """Create user object using model_bakery"""
        self.user = baker.make(
            "drf_user.User", name="test_user", username="my_unique_username"
        )

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if User object created or not"""
        assert User.objects.count() == 1

    @pytest.mark.django_db
    def test_get_full_name(self):
        """Checks that User.get_full_name() method retuns exact name"""
        assert self.user.get_full_name() == "test_user"

    @pytest.mark.django_db
    def test_str_method(self):
        """Check str method"""
        assert str(self.user) == "test_user | my_unique_username"


class TestAuthTransactionModel(TestCase):
    """AuthTransaction Model"""

    def setUp(self) -> None:
        """Create auth_transaction object using model_bakery"""
        self.auth_transaction = baker.make(
            "drf_user.AuthTransaction",
            created_by__name="test_name",
            created_by__username="test_username",
        )

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if AuthTransaction object created or not"""
        assert AuthTransaction.objects.count() == 1

    @pytest.mark.django_db
    def test_str_method(self):
        """Check str method"""
        assert str(self.auth_transaction) == "test_name | test_username"


class TestOTPValidationModel(TestCase):
    """OTPValidation"""

    def setUp(self) -> None:
        """Create otp_validation object using model_bakery"""
        self.otp_validation = baker.make("drf_user.OTPValidation", destination="mobile")

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if OTPValidation object created or not"""
        assert OTPValidation.objects.count() == 1

    @pytest.mark.django_db
    def test_str_method(self):
        """Check str method"""
        assert str(self.otp_validation) == "mobile"
