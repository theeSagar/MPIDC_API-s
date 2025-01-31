from rest_framework import serializers
from .models import CustomUserProfile
from django.contrib.auth.hashers import make_password, check_password


class UserSignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUserProfile  
        fields = ['company_name', 'name', 'mobile_no', 'email_id', 'password']

    def create(self, validated_data):
        """ Hash password before saving to the database """
        
                          
        validated_data['password'] = make_password(validated_data['password'])
        return CustomUserProfile.objects.create(**validated_data)
    
class UserSignSerializer(serializers.Serializer):
    email_id = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email_id = data.get('email_id')
        password = data.get('password')

        try:
            user = user_profile.objects.get(email_id=email_id)
        except user_profile.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password")

        if not check_password(password, user_profile.password):
            raise serializers.ValidationError("Invalid email or password")

        return user