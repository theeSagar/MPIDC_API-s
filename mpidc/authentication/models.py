from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import User


# Create your models here.

class CustomUserProfile(models.Model):
    user = models.OneToOneField(User, null=True, blank=True, on_delete=models.CASCADE)     
    company_name=models.CharField(max_length=255,blank=False)
    name = models.CharField(max_length=255, blank=False, null=False)
    mobile_no = models.CharField(max_length=13, unique=True, null=False, blank=False)
    email_id = models.EmailField(unique=True, null=False, blank=False)
    password = models.CharField(max_length=255, null=False, blank=False)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        """ Hash password before saving to the database """
        if not self.password.startswith('pbkdf2_sha256$'):  
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    def __str__(self):
        return f"{self.company_name} {self.name} {self.mobile_no} {self.email_id} {self.password}"