from django.urls import path

from . import views


app_name = 'drf_user'

urlpatterns = [
    path('login/', views.Login.as_view(), name='Login'),
    path('register/', views.Register.as_view(), name='Register'),
    path('otp/', views.OTPView.as_view(), name='OTP'),
    path('isunique/', views.CheckUnique.as_view(), name='Check Unique'),
    path('account/', views.RetrieveUpdateUserAccountView.as_view(),
         name='Retrieve Update Profile'),
]
