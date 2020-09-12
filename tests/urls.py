"""Test urls"""
from django.urls import include
from django.urls import path

urlpatterns = [
    path("api/user/", include("drf_user.urls")),
]
