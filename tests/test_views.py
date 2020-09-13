"""Tests for drf_user/views.py module"""
import pytest
from django.test import Client
from django.test import TestCase
from django.test.client import RequestFactory
from django.urls import reverse
from model_bakery import baker
from rest_framework import status
from rest_framework.test import force_authenticate

from drf_user.models import AuthTransaction
from drf_user.models import User
from drf_user.views import RetrieveUpdateUserAccountView


class TestLoginView(TestCase):
    """LoginView Test"""

    def setUp(self) -> None:
        """Create Client object to call the API"""
        self.client = Client()

        """Create User object using model_bakery"""
        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            name="user",
            mobile=1234569877,
            is_active=True,
        )

        """Setting user's password"""
        self.user.set_password("pass123")
        self.user.save()

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if the User object is created or not"""
        self.assertEqual(User.objects.count(), 1)

    @pytest.mark.django_db
    def test_successful_login_view(self):
        """Check if the credentials are correct"""
        response = self.client.post(
            reverse("Login"), data={"username": "user", "password": "pass123"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @pytest.mark.django_db
    def test_unsuccessful_login_view(self):
        """Check if the credentials are incorrect"""
        response = self.client.post(
            reverse("Login"), data={"username": "user", "password": "pass1234"}
        )
        self.assertEqual(response.status_code, status.HTTP_422_UNPROCESSABLE_ENTITY)


class TestRetrieveUpdateUserAccountView(TestCase):
    """RetrieveUpdateUserAccountView Test"""

    def setUp(self) -> None:
        """Create RequestFactory object to call the API"""
        self.factory = RequestFactory()

        """Create User object using model_bakery"""
        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            mobile=1234569877,
        )

        """Create auth_transaction object using model_bakery"""
        self.auth_transaction = baker.make(
            "drf_user.AuthTransaction",
            created_by=self.user,
        )

    @pytest.mark.django_db
    def test_object_created(self):
        """Check if AuthTransaction object created or not"""
        assert AuthTransaction.objects.count() == 1

    @pytest.mark.django_db
    def test_get_object_method(self):
        """Create request object using factory"""
        request = self.factory.get(reverse("Retrieve Update Profile"))

        """Simulating that self.user has made the request"""
        request.user = self.user

        """Creates and sets up the RetrieveUpdateUserAccountView"""
        view = RetrieveUpdateUserAccountView()
        view.setup(request)

        self.assertEqual(view.get_object(), self.user)

    @pytest.mark.django_db
    def test_get_user_account_view(self):
        """Create request object using factory"""
        request = self.factory.get(reverse("Retrieve Update Profile"))

        """Authenticating the request"""
        force_authenticate(
            request=request, user=self.user, token=self.auth_transaction.token
        )

        """Creates and sets up the RetrieveUpdateUserAccountView"""
        view = RetrieveUpdateUserAccountView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["username"], self.user.username)

    @pytest.mark.django_db
    def test_update_user_account_view(self):
        """Create request object using factory"""
        request = self.factory.patch(
            reverse("Retrieve Update Profile"),
            data={"username": "updated_username"},
            content_type="application/json",
        )

        """Authenticating the request"""
        force_authenticate(
            request=request, user=self.user, token=self.auth_transaction.token
        )

        """Creates and sets up the RetrieveUpdateUserAccountView"""
        view = RetrieveUpdateUserAccountView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.user.username, "updated_username")


class TestCheckUniqueView(TestCase):
    """CheckUniqueView Test"""

    def setUp(self) -> None:
        """Create Client object to call the API"""
        self.client = Client()

        """Create User object using model_bakery"""
        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            mobile=1234569877,
        )

    @pytest.mark.django_db
    def test_user_object_created(self):
        """Check if User object created or not"""
        self.assertEqual(User.objects.count(), 1)

    @pytest.mark.django_db
    def test_is_unique(self):
        """Check if the user is unique"""
        response = self.client.post(
            reverse("Check Unique"), data={"prop": "username", "value": "user7"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data["data"][0]["unique"])

    @pytest.mark.django_db
    def test_is_not_unique(self):
        """Check if the user is non-unique"""
        response = self.client.post(
            reverse("Check Unique"), data={"prop": "username", "value": "user"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertFalse(response_data["data"][0]["unique"])
