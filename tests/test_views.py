"""Tests for drf_user/views.py module"""
from datetime import timedelta

import pytest
from django.test import override_settings
from django.urls import reverse
from model_bakery import baker
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from drf_user.models import AuthTransaction
from drf_user.models import User
from tests.settings import BASE_DIR


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
    def test_fields_missing(self):
        """Test when API was called without fields then it raises 400"""
        response = self.client.post(self.url, data={})
        self.assertEqual(400, response.status_code)
        self.assertIn(User.USERNAME_FIELD, response.data)
        self.assertIn("password", response.data)

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if the User object is created or not"""
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_successful_login_view(self):
        """Check if the credentials are correct"""
        response = self.client.post(
            self.url, data={"username": "user", "password": "pass123"}
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("token", response.data)
        self.assertIn("refresh_token", response.data)

        # verify that auth transaction object created
        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_login_using_mobile_as_username(self):
        """Test that user can login using mobile number"""
        response = self.client.post(
            self.url, data={"username": "1234569877", "password": "pass123"}
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("token", response.data)
        self.assertIn("refresh_token", response.data)

        # verify that auth transaction object created
        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_login_using_email_as_username(self):
        """Test that user can login using email"""
        response = self.client.post(
            self.url, data={"username": "user@email.com", "password": "pass123"}
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("token", response.data)
        self.assertIn("refresh_token", response.data)

        # verify that auth transaction object created
        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_unsuccessful_login_view(self):
        """Check if the credentials are incorrect"""
        response = self.client.post(
            self.url, data={"username": "user", "password": "pass1234"}
        )

        self.assertEqual(403, response.status_code)
        self.assertIn("username or password is invalid.", response.data["detail"])


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
        self.assertEqual(1, User.objects.count())
        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_get_user_account_view(self):
        """Check Retrieve Update Profile View returns user"""
        self.client.force_authenticate(self.user)
        response = self.client.get(self.url)

        self.assertEqual(200, response.status_code)
        self.assertEqual(self.user.username, response.data["username"])

    @pytest.mark.django_db
    def test_update_username(self):
        """
        Check patch request to Retrieve Update Profile view updates user's username
        """
        self.client.force_authenticate(self.user)
        response = self.client.patch(self.url, {"username": "updated_username"})

        self.assertEqual(200, response.status_code)
        self.assertEqual("updated_username", self.user.username)

    @pytest.mark.django_db
    def test_update_password(self):
        """
        Check patch request to Retrieve Update Profile view updates user's password
        """
        self.client.force_authenticate(self.user)
        self.assertEqual("old_password", self.user.password)

        response = self.client.patch(self.url, {"password": "my_unique_password"})

        self.assertEqual(200, response.status_code)
        self.assertIn("md5", self.user.password)


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
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_is_unique(self):
        """Check if the user is unique"""
        response = self.client.post(self.url, {"prop": "username", "value": "user7"})

        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json()["data"][0]["unique"])

    @pytest.mark.django_db
    def test_is_not_unique(self):
        """Check if the user is not unique"""
        response = self.client.post(self.url, {"prop": "username", "value": "user"})

        self.assertEqual(200, response.status_code)
        self.assertFalse(response.json()["data"][0]["unique"])

    @pytest.mark.django_db
    def test_data_invalid(self):
        """Check CheckUniqueView view raises 422 code when passed data is invalid"""
        response = self.client.post(self.url, {"prop": "invalid", "value": "user"})
        self.assertEqual(422, response.status_code)


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

        self.data_without_mobile = {
            "username": "jake123",
            "password": "test_password",
            "name": "jake",
            "email": "random@django.com",
        }

    @pytest.mark.django_db
    def test_register_with_validated_email_and_mobile(self):
        """Check user creation when validated mobile and email is passed"""

        response = self.client.post(self.url, self.validated_data)

        self.assertEqual(201, response.status_code)
        self.assertEqual("my_username", response.json()["username"])
        self.assertEqual("random_name", response.json()["name"])

    @pytest.mark.django_db
    def test_raise_validation_error_when_email_mobile_not_validated(self):
        """Check view raises Validation Error when mobile and email is not validated"""

        response = self.client.post(self.url, self.not_validated_data)

        self.assertEqual(400, response.status_code)
        self.assertEqual(
            ["The email must be pre-validated via OTP."], response.json()["email"]
        )
        self.assertEqual(
            ["The mobile must be pre-validated via OTP."], response.json()["mobile"]
        )

    @pytest.mark.django_db
    def test_register_user_without_mobile_number(self):
        """
        As we have made mobile optional, user should be able to
        register without passing mobile
        """
        response = self.client.post(self.url, self.data_without_mobile)
        self.assertEqual(201, response.status_code)
        self.assertEqual("jake", response.json()["name"])

    @pytest.mark.django_db
    def test_register_user_with_mobile(self):
        """
        Checks when setting `MOBILE_OPTIONAL` is set to False
            - it gives 400 if mobile is not passed
            - it gives proper error message
            - user object is being created when mobile is passed
        """
        with override_settings(USER_SETTINGS={"MOBILE_OPTIONAL": False}):
            response = self.client.post(self.url, self.data_without_mobile)
            self.assertEqual(400, response.status_code)
            self.assertEqual("Mobile is required.", response.json()["error"])

            response = self.client.post(self.url, self.validated_data)
            self.assertEqual(201, response.status_code)
            self.assertEqual("1234567890", response.json()["mobile"])


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

    @pytest.mark.django_db
    def test_request_otp_on_email(self):
        """
        Checks when destination and email is passed to OTPView is sends otp on mail
        """

        response = self.client.post(
            self.url, {"destination": "email@django.com", "email": "email@django.com"}
        )

        self.assertEqual(201, response.status_code)
        self.assertEqual("Message sent successfully!", response.json()["message"])

    @pytest.mark.django_db
    def test_request_otp_on_email_and_mobile(self):
        """
        Checks when mobile as destination and email is passed to OTPView
        it sends otp on mail as well as on mobile
        """

        response = self.client.post(
            self.url, {"destination": 1231242492, "email": "email@django.com"}
        )

        self.assertEqual(201, response.status_code)
        self.assertEqual("Message sent successfully!", response.json()["message"])

    @pytest.mark.django_db
    def test_raise_api_exception_when_email_invalid(self):
        """Checks OTPView raises validation error when email/mobile is invalid"""

        response = self.client.post(
            self.url, {"destination": "a.b", "email": "abc@d.com"}
        )

        self.assertEqual(500, response.status_code)
        self.assertEqual(
            "Server configuration error occurred: Invalid recipient.",
            response.json()["detail"],
        )

    @pytest.mark.django_db
    def test_raise_validation_error_when_email_not_response_when_user_is_new(self):
        """
        Checks OTPView raises validation error when new user
        only passes destination and not email
        """

        response = self.client.post(self.url, {"destination": "email@django.com"})

        self.assertEqual(
            ["email field is compulsory while verifying a non-existing user's OTP."],
            response.json()["non_field_errors"],
        )
        self.assertEqual(400, response.status_code)

    @pytest.mark.django_db
    def test_raise_validation_error_when_is_login_response_when_user_is_new(self):
        """
        Checks OTPView raises validation error when new user
        only passes is_login
        """

        response = self.client.post(
            self.url, {"destination": "email@django.com", "is_login": True}
        )

        self.assertEqual(
            "No user exists with provided details", response.json()["detail"]
        )
        self.assertEqual(404, response.status_code)

    @pytest.mark.django_db
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

        self.assertEqual(202, response.status_code)
        assert "OTP Validated successfully!" in response.json()["OTP"]

    @pytest.mark.django_db
    def test_is_login_in_response(self):
        """Check user login with OTP"""

        response = self.client.post(
            self.url,
            {"destination": "user@example.com", "verify_otp": 888383, "is_login": True},
        )

        self.assertEqual(202, response.status_code)


class TestOTPLoginView(APITestCase):
    """OTP Login View"""

    def setUp(self) -> None:
        """Setup Test Data"""
        self.url = reverse("OTP-Register-LogIn")

        # create user
        self.user = baker.make(
            "drf_user.User",
            username="my_user",
            email="my_user@django.com",
            mobile=2848482848,
        )
        # create otp of registered user
        self.user_otp = baker.make(
            "drf_user.OTPValidation", destination="my_user@django.com", otp=437474
        )

        # generate otp for random user
        self.random_user_otp = baker.make(
            "drf_user.OTPValidation", destination="random@django.com", otp=888383
        )
        self.data = {
            "name": "random_name",
            "email": "random@django.com",
            "mobile": 1234567890,
        }
        self.data_with_incorrect_email_mobile = {
            "name": "name",
            "email": "r@o.com",
            "mobile": 97,
        }
        self.data_with_correct_otp = {
            "name": "random_name",
            "email": "random@django.com",
            "mobile": 1234567890,
            "verify_otp": 888383,
        }
        self.data_with_incorrect_otp = {
            "name": "random_name",
            "email": "random@django.com",
            "mobile": 1234567890,
            "verify_otp": 999999,
        }
        self.data_registered_user = {
            "name": "my_user",
            "email": "my_user@django.com",
            "mobile": 2848482848,
            "verify_otp": 437474,
        }
        self.data_registered_user_with_different_mobile = {
            "name": "my_user",
            "email": "my_user@django.com",
            "mobile": 2846482848,
            "verify_otp": 437474,
        }
        self.data_registered_user_with_different_email = {
            "name": "my_user",
            "email": "ser@django.com",
            "mobile": 2848482848,
            "verify_otp": 437474,
        }
        self.data_random_user = {
            "name": "test_user1",
            "email": "test_user1@django.com",
            "mobile": 2848444448,
            "verify_otp": 585858,
        }

    @pytest.mark.django_db
    def test_when_only_name_is_passed(self):
        """Check when only name is passed as data then api raises 400"""
        response = self.client.post(self.url, data={"name": "test"}, format="json")

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["email"])
        self.assertEqual(["This field is required."], response.json()["mobile"])

    @pytest.mark.django_db
    def test_when_name_email_is_passed(self):
        """Check when name and email is passed as data, then API raises 400"""

        response = self.client.post(
            self.url, data={"name": "test", "email": "test@random.com"}, format="json"
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["mobile"])

    @pytest.mark.django_db
    def test_when_name_mobile_is_passed(self):
        """Check when name and mobile is passed as data, then API raises 400"""

        response = self.client.post(
            self.url, data={"name": "test", "mobile": 1234838884}, format="json"
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["email"])

    @pytest.mark.django_db
    def test_when_email_mobile_is_passed(self):
        """Check when email and mobile is passed as data, then API raises 400"""

        response = self.client.post(
            self.url,
            data={"email": "test@example.com", "mobile": 1234838884},
            format="json",
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["name"])

    @pytest.mark.django_db
    def test_sent_otp_when_name_email_mobile_is_passed(self):
        """
        Check when name, email, mobile is passed then OTP
        is sent on user's email/mobile by API
        """
        response = self.client.post(self.url, data=self.data, format="json")

        self.assertEqual(201, response.status_code)
        self.assertEqual(
            "OTP has been sent successfully.", response.json()["email"]["otp"]
        )
        self.assertEqual(
            "OTP has been sent successfully.", response.json()["mobile"]["otp"]
        )

    @pytest.mark.django_db
    def test_login_with_incorrect_otp_for_registered_user(self):
        """Check when data with correct otp is passed, token is generated or not"""

        response = self.client.post(
            self.url, data=self.data_with_incorrect_otp, format="json"
        )

        self.assertEqual(403, response.status_code)
        self.assertEqual(
            "OTP Validation failed! 2 attempts left!", response.json()["detail"]
        )

    @pytest.mark.django_db
    def test_login_with_incorrect_otp_for_new_user_without_validated_otp(self):
        """Check when data without validated otp is passed, raises 404"""

        response = self.client.post(self.url, data=self.data_random_user, format="json")

        self.assertEqual(404, response.status_code)
        self.assertEqual(
            "No pending OTP validation request found for provided destination. "
            "Kindly send an OTP first",
            response.json()["detail"],
        )

    @pytest.mark.django_db
    def test_login_with_correct_otp_for_new_user(self):
        """
        Check when data with correct otp is passed, token is generated
        and user is created
        """

        response = self.client.post(
            self.url, data=self.data_with_correct_otp, format="json"
        )

        self.assertEqual(202, response.status_code)
        self.assertContains(text="token", response=response, status_code=202)
        self.assertTrue(User.objects.get(email="random@django.com"))

    @pytest.mark.django_db
    def test_login_with_incorrect_email_mobile(self):
        """
        Checks when wrong data is passed, raises server error
        """
        # this test case verifies that mobile isn't validated by drfaddons,
        # will update this test case after fixing drfaddons
        response = self.client.post(
            self.url, data=self.data_with_incorrect_email_mobile, format="json"
        )

        # TODO: update this test case to assert status_code == 400
        #  when drf_addons is updated
        self.assertEqual(500, response.status_code)
        self.assertEqual(
            "Server configuration error occurred: Invalid recipient.",
            response.json()["detail"],
        )

    @pytest.mark.django_db
    def test_login_with_different_email(self):
        """
        Checks when a registered user passed different email,
        raises validation error or not
        """
        response = self.client.post(
            self.url, data=self.data_registered_user_with_different_email, format="json"
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(
            [
                "Your account is registered with 2848482848 does not has ser@django.com as "  # noqa:E501
                "registered email. Please login directly via OTP with your mobile."
            ],
            response.json()["non_field_errors"],
        )

    @pytest.mark.django_db
    def test_login_with_different_mobile(self):
        """
        Checks when a registered user passed different mobile,
        raises validation error or not
        """
        response = self.client.post(
            self.url,
            data=self.data_registered_user_with_different_mobile,
            format="json",
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(
            [
                "Your account is registered with my_user@django.com does not has 2846482848"  # noqa:E501
                " as registered mobile. Please login directly via OTP with your email."
            ],
            response.json()["non_field_errors"],
        )


class TestPasswordResetView(APITestCase):
    """PasswordResetView Test"""

    def setUp(self) -> None:
        """SetUp test data"""
        self.url = reverse("reset_user_password")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            name="user",
            mobile=1234569877,
            is_active=True,
        )

        # create otp of registered user
        self.user_otp = baker.make(
            "drf_user.OTPValidation", destination="user@email.com", otp=437474
        )

        self.data_correct_otp = {
            "otp": 437474,
            "email": "user@email.com",
            "password": "test@123",
        }

        self.data_incorrect_otp = {
            "otp": 767474,
            "email": "user@email.com",
            "password": "test@123",
        }

        self.data_incorrect_email = {
            "otp": 437474,
            "email": "meh@email.com",
            "password": "test@123",
        }

        self.user.set_password("pass123")
        self.user.save()

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if the User object is created or not"""
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_when_nothing_is_passed(self):
        """Check when nothing is passed as data then api raises 400"""
        response = self.client.post(self.url, data={}, format="json")

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["otp"])
        self.assertEqual(["This field is required."], response.json()["email"])
        self.assertEqual(["This field is required."], response.json()["email"])

    @pytest.mark.django_db
    def test_when_incorrect_email_passed(self):
        """Check when incorrect email is passed as data then api raises 404"""
        response = self.client.post(
            self.url, data=self.data_incorrect_email, format="json"
        )

        self.assertEqual(404, response.status_code)

    @pytest.mark.django_db
    def test_when_incorrect_otp_passed(self):
        """Check when incorrect otp is passed as data then api raises 403"""
        response = self.client.post(
            self.url, data=self.data_incorrect_otp, format="json"
        )

        self.assertEqual(403, response.status_code)

    @pytest.mark.django_db
    def test_when_correct_otp_email_passed(self):
        """Check when correct otp and email is passed as data then api raises 202"""
        response = self.client.post(self.url, data=self.data_correct_otp, format="json")

        self.assertEqual(202, response.status_code)


class TestUploadImageView(APITestCase):
    """UploadImageView Test"""

    def setUp(self) -> None:
        """SetUp test data"""
        self.url = reverse("upload_profile_image")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            name="user",
            mobile=1234569877,
            is_active=True,
        )

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if the User object is created or not"""
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_when_nothing_is_passed(self):
        """Check when nothing is passed as data then api raises 400"""

        self.client.force_authenticate(self.user)
        response = self.client.post(self.url, data={}, format="multipart")

        self.assertEqual(400, response.status_code)
        self.assertEqual("No file was submitted.", response.json()["profile_image"][0])

    @pytest.mark.django_db
    def test_when_upload_image_passed(self):
        """Check when image is passed as data then api raises 201"""

        self.client.force_authenticate(self.user)
        with open(f"{BASE_DIR}/tests/fixtures/test.jpg", "rb") as f:
            response = self.client.post(
                self.url, data={"profile_image": f}, format="multipart"
            )

        self.assertEqual(201, response.status_code)
        self.assertEqual("Profile Image Uploaded.", response.json()["detail"])


class TestCustomTokenRefreshView(APITestCase):
    """CustomTokenRefreshView"""

    def setUp(self) -> None:
        """SetUp test data"""
        self.url = reverse("refresh_token")

        self.login_url = reverse("Login")

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

    def test_fields_missing(self):
        """Test when API was called without refresh_token then it raises 400"""
        res = self.client.post(self.url, data={})
        self.assertEqual(400, res.status_code)
        self.assertIn("refresh", res.data)

    def test_api_should_return_401_if_token_invalid(self):
        """Test api returns 401 when refresh token is invalid."""
        token = RefreshToken()
        del token["exp"]

        response = self.client.post(self.url, data={"refresh": str(token)})
        self.assertEqual(401, response.status_code)
        self.assertEqual("token_not_valid", response.data["code"])

        token.set_exp(lifetime=-timedelta(seconds=1))

        response = self.client.post(self.url, data={"refresh": str(token)})
        self.assertEqual(401, response.status_code)
        self.assertEqual("token_not_valid", response.data["code"])

    @pytest.mark.django_db
    def test_it_should_return_access_token_if_everything_ok(self):
        """Test when refresh token is valid then it generated new access token"""
        # generate tokens using login api
        login_response = self.client.post(
            self.login_url, data={"username": "user", "password": "pass123"}
        )

        response = self.client.post(
            self.url, data={"refresh": str(login_response.data["refresh_token"])}
        )

        self.assertEqual(200, response.status_code)
        self.assertIn("token", response.data)
