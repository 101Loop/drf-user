from django.urls import path
from . import views


app_name = 'drf_user'

urlpatterns = [
    path('login/', views.Login.as_view(), name='Login'),
    path('register/', views.Register.as_view(), name='Register'),
    path('sendotp/', views.SendOTP.as_view(), name='Send OTP'),
    path('verifyotp/', views.VerifyOTP.as_view(), name='Verify OTP'),
    path('loginotp/', views.LoginOTP.as_view(), name='Login OTP'),
    path('isunique/', views.CheckUnique.as_view(), name='Check Unique'),
]
