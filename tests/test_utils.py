"""Tests for drf_user/utils.py module"""
import pytest
from django.test import TestCase
from model_bakery import baker

from drf_user import utils as utils
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
