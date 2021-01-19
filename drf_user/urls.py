"""Urls module for drf-user"""
from django.urls import path

from drf_user import views

app_name = "drf_user"

urlpatterns = [
    # ex: api/user/login/
    path("login/", views.LoginView.as_view(), name="Login"),
    # ex: api/user/register/
    path("register/", views.RegisterView.as_view(), name="Register"),
    # ex: api/user/otp/
    path("otp/", views.OTPView.as_view(), name="OTP"),
    # ex: api/user/otpreglogin/
    path("otpreglogin/", views.OTPLoginView.as_view(), name="OTP-Register-LogIn"),
    # ex: api/user/isunique/
    path("isunique/", views.CheckUniqueView.as_view(), name="Check Unique"),
    # ex: api/user/account/
    path(
        "account/",
        views.RetrieveUpdateUserAccountView.as_view(),
        name="Retrieve Update Profile",
    ),
    # ex: api/user/password/reset/
    path(
        "password/reset/", views.PasswordResetView.as_view(), name="reset_user_password"
    ),
    # ex: api/user/upload-image/
    path("upload-image/", views.UploadImageView.as_view(), name="upload_profile_image"),
    # ex: api/user/refresh-token/
    path(
        "refresh-token/", views.CustomTokenRefreshView.as_view(), name="refresh_token"
    ),
]
