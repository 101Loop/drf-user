import pytest
from django.test import TestCase
from model_bakery import baker

from drf_user.models import AuthTransaction
from drf_user.models import OTPValidation
from drf_user.models import User


class TestUserModel(TestCase):
    """ User Model Tests"""

    def setUp(self) -> None:
        self.user = baker.make(
            "drf_user.User", name="test_user", username="my_unique_username"
        )

    @pytest.mark.django_db
    def test_created(self):
        assert User.objects.count() == 1

    @pytest.mark.django_db
    def test_get_full_name(self):
        user = self.user
        assert user.get_full_name() == "test_user"

    @pytest.mark.django_db
    def test_str_method(self):
        user = self.user
        assert str(user) == "test_user | my_unique_username"


class TestAuthTransactionModel(TestCase):
    """AuthTransaction Model"""

    def setUp(self) -> None:
        self.auth_transaction = baker.make(
            "drf_user.AuthTransaction",
            created_by__name="test_name",
            created_by__username="test_username",
        )

    @pytest.mark.django_db
    def test_object_created(self):
        assert AuthTransaction.objects.count() == 1

    @pytest.mark.django_db
    def test_str_method(self):
        assert str(self.auth_transaction) == "test_name | test_username"


class TestOTPValidationModel(TestCase):
    """OTPValidation"""

    def setUp(self) -> None:
        self.otp_validation = baker.make("drf_user.OTPValidation", destination="mobile")

    @pytest.mark.django_db
    def test_object_created(self):
        assert OTPValidation.objects.count() == 1

    @pytest.mark.django_db
    def test_str_method(self):
        assert str(self.otp_validation) == "mobile"
