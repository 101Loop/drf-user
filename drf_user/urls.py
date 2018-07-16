from django.urls import path
from . import views


app_name = 'drf_user'

urlpatterns = [
    # ex: api/user/login/
    path('login/', views.Login.as_view(), name='Login'),
    # ex: api/user/register/
    path('register/', views.Register.as_view(), name='Register'),
    # ex: api/user/sendotp/
    path('sendotp/', views.SendOTP.as_view(), name='Send OTP'),
    # ex: api/user/verifyotp/
    path('verifyotp/', views.VerifyOTP.as_view(), name='Verify OTP'),
    # ex: api/user/loginotp/
    path('loginotp/', views.LoginOTP.as_view(), name='Login OTP'),
    # ex: api/user/isunique/
    path('isunique/', views.CheckUnique.as_view(), name='Check Unique'),
    # ex: api/user/changepassword/
    path('changepassword/', views.ChangePassword.as_view(), name='Change Password'),
    # ex: api/user/updateprofile/
    path('updateprofile/', views.UpdateProfileView.as_view(), name='Update-Profile'),
]
