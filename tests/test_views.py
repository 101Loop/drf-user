"""Tests for drf_user/views.py module"""
import pytest
from django.test import Client
from django.test import TestCase
from django.urls import reverse
from model_bakery import baker
from rest_framework import status

from drf_user.models import User


class LoginViewTest(TestCase):
    """Login View Test"""

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
