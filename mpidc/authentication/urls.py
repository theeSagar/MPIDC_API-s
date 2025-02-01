from django.urls import path
from django.conf import settings
from .views import *

urlpatterns = [
    path("signUp/", SignUp.as_view(), name="SignUp"),
    path("signIn/", SignIn.as_view(), name="SignIn"),
    path("User-Profile/", UserProfile.as_view(),name="UserProfile"),
    path("forgot-password-request/", ForgotPasswordRequest.as_view(), name="forgot_password_request"),
    path("forgot-password-verify/", ForgotPasswordVerify.as_view(), name="forgot_password_verify")
]