"""Tests for drf_user/views.py module"""
import pytest
from django.urls import reverse
from model_bakery import baker
from rest_framework.test import APITestCase

from drf_user.models import AuthTransaction
from drf_user.models import User


class TestLoginView(APITestCase):
    """LoginView Test"""

    def setUp(self) -> None:
        """SetUp test data"""
        self.url = reverse("Login")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            name="user",
            mobile=1234569877,
            is_active=True,
        )

        self.user.set_password("pass123")
        self.user.save()

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if the User object is created or not"""
        assert User.objects.count() == 1

    @pytest.mark.django_db
    def test_successful_login_view(self):
        """Check if the credentials are correct"""
        response = self.client.post(
            self.url, data={"username": "user", "password": "pass123"}
        )

        assert response.status_code == 200

    @pytest.mark.django_db
    def test_unsuccessful_login_view(self):
        """Check if the credentials are incorrect"""
        response = self.client.post(
            self.url, data={"username": "user", "password": "pass1234"}
        )

        assert response.status_code == 422


class TestRetrieveUpdateUserAccountView(APITestCase):
    """RetrieveUpdateUserAccountView Test"""

    def setUp(self) -> None:
        """SetUp test data"""
        self.url = reverse("Retrieve Update Profile")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            mobile=1234569877,
            password="old_password",
        )

        self.auth_transaction = baker.make(
            "drf_user.AuthTransaction",
            created_by=self.user,
        )

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if AuthTransaction object created or not"""
        assert User.objects.count() == 1
        assert AuthTransaction.objects.count() == 1

    @pytest.mark.django_db
    def test_get_user_account_view(self):
        """Check Retrieve Update Profile View returns user"""
        self.client.force_authenticate(self.user)
        response = self.client.get(self.url)

        assert response.status_code == 200
        assert response.data["username"] == self.user.username

    @pytest.mark.django_db
    def test_update_username(self):
        """
        Check patch request to Retrieve Update Profile view updates user's username
        """
        self.client.force_authenticate(self.user)
        response = self.client.patch(self.url, {"username": "updated_username"})

        assert response.status_code == 200
        assert self.user.username == "updated_username"

    @pytest.mark.django_db
    def test_update_password(self):
        """
        Check patch request to Retrieve Update Profile view updates user's password
        """
        self.client.force_authenticate(self.user)
        assert self.user.password == "old_password"

        response = self.client.patch(self.url, {"password": "my_unique_password"})

        assert response.status_code == 200
        assert self.user.password == "my_unique_password"


class TestCheckUniqueView(APITestCase):
    """CheckUniqueView Test"""

    def setUp(self) -> None:
        """SetUp test data"""
        self.url = reverse("Check Unique")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            mobile=1234569877,
        )

    @pytest.mark.django_db
    def test_user_object_created(self):
        """Check if User object created or not"""
        assert User.objects.count() == 1

    @pytest.mark.django_db
    def test_is_unique(self):
        """Check if the user is unique"""
        response = self.client.post(self.url, {"prop": "username", "value": "user7"})
        assert response.status_code == 200
        self.assertTrue(response.json()["data"][0]["unique"])

    @pytest.mark.django_db
    def test_is_not_unique(self):
        """Check if the user is not unique"""
        response = self.client.post(self.url, {"prop": "username", "value": "user"})
        assert response.status_code == 200
        self.assertFalse(response.json()["data"][0]["unique"])

    @pytest.mark.django_db
    def test_data_invalid(self):
        """Check CheckUniqueView view raises 422 code when passed data is invalid"""
        response = self.client.post(self.url, {"prop": "invalid", "value": "user"})
        assert response.status_code == 422


class TestRegisterView(APITestCase):
    """RegisterView Test"""

    def setUp(self) -> None:
        """SetUp test data"""
        # pre validate email
        self.validated_email = baker.make(
            "drf_user.OTPValidation", destination="random@django.com", is_validated=True
        )
        # pre validate mobile
        self.validated_mobile = baker.make(
            "drf_user.OTPValidation", destination="1234567890", is_validated=True
        )
        self.url = reverse("Register")
        self.validated_data = {
            "username": "my_username",
            "password": "test_password",
            "name": "random_name",
            "email": "random@django.com",
            "mobile": 1234567890,
        }
        self.not_validated_data = {
            "username": "random",
            "password": "test_password",
            "name": "random_name",
            "email": "random@example.com",
            "mobile": 8800880080,
        }

    def test_register_with_validated_email_and_mobile(self):
        """Check user creation when validated mobile and email is passed"""

        response = self.client.post(self.url, self.validated_data)

        assert response.status_code == 201
        assert "my_username" in response.json()["username"]
        assert "random_name" in response.json()["name"]

    def test_raise_validation_error_when_email_mobile_not_validated(self):
        """Check view raises Validation Error when mobile and email is not validated"""

        response = self.client.post(self.url, self.not_validated_data)

        assert response.status_code == 400
        assert "The email must be pre-validated via OTP." in response.json()["email"]
        assert "The mobile must be pre-validated via OTP." in response.json()["mobile"]


class TestOTPView(APITestCase):
    """OTPView Test"""

    def setUp(self) -> None:
        """SetUp test data"""
        self.user = baker.make("drf_user.User", email="user@example.com")
        self.otp_user = baker.make(
            "drf_user.OTPValidation", destination="user@example.com", otp=888383
        )
        self.otp_object = baker.make(
            "drf_user.OTPValidation", destination="email@django.com", otp=123456
        )
        self.url = reverse("OTP")

    def test_request_otp_on_email(self):
        """
        Checks when destination and email is passed to OTPView is sends otp on mail
        """

        response = self.client.post(
            self.url, {"destination": "email@django.com", "email": "email@django.com"}
        )

        assert response.status_code == 201
        assert "Message sent successfully!" in response.json()["message"]

    def test_request_otp_on_email_and_mobile(self):
        """
        Checks when mobile as destination and email is passed to OTPView
        it sends otp on mail as well as on mobile
        """

        response = self.client.post(
            self.url, {"destination": 1231242492, "email": "email@django.com"}
        )

        assert response.status_code == 201
        assert "Message sent successfully!" in response.json()["message"]

    def test_raise_api_exception_when_email_invalid(self):
        """Checks OTPView raises validation error when email/mobile is invalid"""

        response = self.client.post(
            self.url, {"destination": "a.b", "email": "abc@d.com"}
        )

        assert response.status_code == 500
        assert "Server configuration error occured:" in response.json()["detail"]

    def test_raise_validation_error_when_email_not_response_when_user_is_new(self):
        """
        Checks OTPView raises validation error when new user
        only passes destination and not email
        """

        response = self.client.post(self.url, {"destination": "email@django.com"})

        assert (
            "email field is compulsory while verifying a non-existing user's OTP."
            in response.json()["non_field_errors"]
        )
        assert response.status_code == 400

    def test_raise_validation_error_when_is_login_response_when_user_is_new(self):
        """
        Checks OTPView raises validation error when new user
        only passes is_login
        """

        response = self.client.post(
            self.url, {"destination": "email@django.com", "is_login": True}
        )

        assert "No user exists with provided details" in response.json()["detail"]
        assert response.status_code == 404

    def test_verify_otp_in_response(self):
        """Check otp validation"""
        response = self.client.post(
            self.url,
            {
                "destination": "email@django.com",
                "email": "email@django.com",
                "verify_otp": 123456,
            },
        )

        assert response.status_code == 202
        assert "OTP Validated successfully!" in response.json()["OTP"]

    def test_is_login_in_response(self):
        """Check user login with OTP"""

        response = self.client.post(
            self.url,
            {"destination": "user@example.com", "verify_otp": 888383, "is_login": True},
        )

        assert response.status_code == 202
