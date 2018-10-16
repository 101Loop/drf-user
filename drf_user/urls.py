from django.urls import path

from . import views


app_name = 'drf_user'

urlpatterns = [
    # ex: api/user/login/
    path('login/', views.Login.as_view(), name='Login'),
    # ex: api/user/register/
    path('register/', views.Register.as_view(), name='Register'),
    # ex: api/user/sendotp/
    path('otp/', views.OTPView.as_view(), name='OTP'),
    # ex: api/user/isunique/
    path('isunique/', views.CheckUnique.as_view(), name='Check Unique'),
    # ex: api/user/updateprofile/
    path('account/', views.RetrieveUpdateUserAccountView.as_view(), name='Retrieve Update Profile'),
]
