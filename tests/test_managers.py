"""Tests for drf_user/managers.py module"""
from unittest import TestCase

import pytest
from faker import Faker

from drf_user.models import User

faker: Faker = Faker()


class TestUserManager(TestCase):
    """TestUserManager

    Check that all methods ipren UserManager works as expected.
    """

    @pytest.mark.django_db
    def test_create_normal_user_without_mobile(self):
        """Check that normal user is created without mobile number"""
        # given
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()

        # when
        user = User.objects.create_user(
            username=user_name, email=email, password=password, name=name
        )

        # then
        self.assertEqual(name, user.name)
        self.assertEqual(user_name, user.username)
        self.assertEqual(email, user.email)
        self.assertIsNone(user.mobile)
        self.assertFalse(user.is_superuser)

    @pytest.mark.django_db
    def test_create_normal_user_with_mobile(self):
        """Check that normal user is created with mobile number"""
        # given
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()
        mobile = faker.phone_number()

        # when
        user = User.objects.create_user(
            username=user_name, email=email, password=password, name=name, mobile=mobile
        )

        # then
        self.assertEqual(name, user.name)
        self.assertEqual(user_name, user.username)
        self.assertEqual(email, user.email)
        self.assertEqual(mobile, user.mobile)
        self.assertFalse(user.is_superuser)

    @pytest.mark.django_db
    def test_create_super_user_without_mobile(self):
        """Check that super user is created without mobile number"""
        # given
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()

        # when
        user = User.objects.create_superuser(
            username=user_name, email=email, password=password, name=name
        )

        # then
        self.assertEqual(name, user.name)
        self.assertEqual(user_name, user.username)
        self.assertEqual(email, user.email)
        self.assertIsNone(user.mobile)
        self.assertTrue(user.is_superuser)

    @pytest.mark.django_db
    def test_create_super_user_with_mobile(self):
        """Check that super user is created with mobile number"""
        # given
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()
        mobile = faker.phone_number()

        # when
        user = User.objects.create_superuser(
            username=user_name, email=email, password=password, name=name, mobile=mobile
        )

        # then
        self.assertEqual(name, user.name)
        self.assertEqual(user_name, user.username)
        self.assertEqual(email, user.email)
        self.assertEqual(mobile, user.mobile)
        self.assertTrue(user.is_superuser)

    @pytest.mark.django_db
    def test_create_super_user_raises_value_error_when_is_super_user_false(self):
        """
        Check that create_super_user raises value error if is_superuser set to False
        """
        # given
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()
        mobile = faker.phone_number()

        # then
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username=user_name,
                email=email,
                password=password,
                name=name,
                mobile=mobile,
                is_superuser=False,
            )

    @pytest.mark.django_db
    def test_create_super_user_raises_value_error_when_is_staff_false(self):
        """
        Check that create_super_user raises value error if is_staff set to False
        """
        # given
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()
        mobile = faker.phone_number()

        # then
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username=user_name,
                email=email,
                password=password,
                name=name,
                mobile=mobile,
                is_staff=False,
            )
