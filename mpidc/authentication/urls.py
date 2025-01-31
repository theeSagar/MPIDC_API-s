from django.urls import path
from django.conf import settings
from .views import *

urlpatterns = [
    path("signUp/", SignUp.as_view(), name="SignUp"),
    path("signIn/", SignIn.as_view(), name="SignIn"),
    path("User-Profile/", UserProfile.as_view(),name="UserProfile")
]