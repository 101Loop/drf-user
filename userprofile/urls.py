from django.conf.urls import url
from . import views


app_name = 'userprofileapp'

urlpatterns = [
    url(r'login/$', views.Login.as_view(), name='Login'),
    url(r'register/$', views.Register.as_view(), name='Register'),
    url(r'sendotp/$', views.SendOTP.as_view(), name='Send OTP'),
    url(r'verifyotp/$', views.VerifyOTP.as_view(), name='Verify OTP'),
    url(r'isunique/$', views.CheckUnique.as_view(), name='Check Unique'),
]
