from django.contrib.auth.models import User  
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status
from .models import CustomUserProfile
from .serializers import UserSignupSerializer
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client
from django.conf import settings
import secrets
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail





class SignUp(APIView):
    def post(self, request):
        data = request.data

        mobile_no = data.get('mobile_no')
        email_id = data.get('email_id')

        # this check if the required feild/keys are present or not
        missing_fields = [
            field for field in ["company_name", "name", "mobile_no", "email_id", "password"]
            if field not in request.data or not request.data[field]
        ]

        if missing_fields:
            return Response(
                {"status":False,
                "message": f"Missing required fields: {', '.join(missing_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not mobile_no.startswith("+91"):
            return Response(
                {"status":"Mobile number should start with +91"},
                status=status.HTTP_404_NOT_FOUND
            )
        if len(mobile_no) != 13 or not mobile_no[3:].isdigit():
            return Response(
                {"status": "Mobile number must be 10 digits long after '+91'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # this checks if the user with same mobile_no and email_id is present in db 
        existing_user = CustomUserProfile.objects.filter(mobile_no=mobile_no).exists() or CustomUserProfile.objects.filter(email_id=email_id).exists()
        if existing_user:
            return Response(
                {"status":"User with this email or mobile number already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if '@' not in email_id:
            return Response (
                {"status": "Email must contain '@'.",
                
            }, status=status.HTTP_400_BAD_REQUEST
            )
        # Validate the serializer
        serializer = UserSignupSerializer(data=data)
        if serializer.is_valid():
            
            user = User.objects.create_user(
                username=email_id,  # Use email as username
                password=data['password'],
            )
            custom_user_profile = CustomUserProfile(
                user=user,
                company_name=data['company_name'],
                name=data['name'],
                mobile_no=mobile_no,
                email_id=email_id,
            )
            custom_user_profile.save()

            return Response(
                {   "status":True,
                    "message": "User registered successfully",
                    "username": custom_user_profile.name,
                    "email_id": custom_user_profile.email_id,
                    "mobile_no": custom_user_profile.mobile_no,
                   
                },
                status=status.HTTP_201_CREATED
            )

        errors = serializer.errors
        formatted_errors = {field: errors[field][0] for field in errors}  # Extract the first error message
        return Response(
            {"status":False,
            "message":"Validation failed", "errors": formatted_errors},
            status=status.HTTP_400_BAD_REQUEST
        )

class SignIn(APIView):
    def post(self, request):
        data=request.data
        try:
            email_id = data.get("email_id").strip()
            password = data.get("password").strip()

            if not email_id or not password:
                return Response(
                    {"status": "Email and password are required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Authenticate the user using Django's authenticate function
            user = authenticate(request, username=email_id, password=password)

            if user is not None:
            # If the user is authenticated, check if token exists or generate one
                token, created = Token.objects.get_or_create(user=user)

                return Response(
                    {
                        "message": "Login successful",
                        "token": token.key,
                        "username": user.username,
                        # "email_id":user.username
                        # "email_id": user.email,
                    },
                    status=status.HTTP_200_OK
                )
            else:
                # This handles invalid credentials (wrong password or username)
                return Response(
                    {"status":"Invalid credentials."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except KeyError:
            result = {"status": False, "message": "Invalid Input"}
            return Response(result, status=status.HTTP_400_BAD_REQUEST)
        
class UserProfile(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def get(self, request):
        user = request.user
        try:
            custom_profile = CustomUserProfile.objects.get(user=user)

            user_data = {
                "username": user.username,
                "email_id": custom_profile.email_id,
                "mobile_no": custom_profile.mobile_no,
                "name": custom_profile.name,
            }

            return Response(user_data, status=status.HTTP_200_OK)
        except CustomUserProfile.DoesNotExist:
            return Response(
                {"status": "User profile not found."},
                status=status.HTTP_404_NOT_FOUND
            )

class ForgotPasswordRequest(APIView):

    def post(self, request):
        mobile_no = request.data.get('mobile_no')
        # email_id =request.get("email_id")
        print("_____________,",mobile_no)
        
        if not mobile_no:
            return Response({"status": "Mobile number is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate mobile number format
        if not mobile_no.startswith('+91') and not len(mobile_no)==12:
            return Response(
                {"status": "Mobile number must start with country code (e.g., +91) adn should be of 12 digits only."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user_profile = CustomUserProfile.objects.get(mobile_no=mobile_no)
            print(user_profile)
        except CustomUserProfile.DoesNotExist:
            return Response({"status": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP static as per now
        # otp = secrets.randbelow(1_000_000)
        # otp = f"{otp:06d}"
        otp='123456'
        
        # Saving opt and expiry time in db
        user_profile.otp = otp
        user_profile.otp_expiry = timezone.now() + timedelta(minutes=15)
        user_profile.save()
        # # Initialize Twilio client
        # client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        
        # try:
        #     # Send SMS via Twilio
        #     message = client.messages.create(
        #         body=f'Your OTP is: {otp}',
        #         from_=settings.TWILIO_PHONE_NUMBER,  
        #         to=mobile_no                        
        #     )
            
        #     # Optional: Store the message SID for tracking
        #     user_profile.twilio_message_sid = message.sid
        #     user_profile.save()

        # except TwilioRestException as e:
        #     # Handle Twilio errors
        #     return Response(
        #         {"status": f"SMS sending failed: {str(e)}"},
        #         status=status.HTTP_500_INTERNAL_SERVER_ERROR
        #     )
        email_id=user_profile.email_id
        print("_______+_+_+___",email_id)
        try:
            send_mail(
                subject='Your OTP for Password Reset',  # Email subject
                message=f'Your OTP for password reset is: {otp} and valid for 15 minutes.', 
                from_email=settings.DEFAULT_FROM_EMAIL,  # Sender email address
                recipient_list=[email_id],
                fail_silently=False,  
            )
        except Exception as e:
            return Response(
                {"status": f"Failed to send OTP via email: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        return Response({
            "status": True,
            "message": f"OTP sent successfully to your registered mobile number ending with +91XXXXX{mobile_no[-3:]} and email {email_id}"
        }, status=status.HTTP_200_OK)
class ForgotPasswordVerify(APIView):
    def post(self, request):
        mobile_no = request.data.get('mobile_no')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not all([mobile_no, otp, new_password]):
            return Response({"status":False
                             ,"message": "All fields are required"},
                              status=status.HTTP_400_BAD_REQUEST)

        try:
            user_profile = CustomUserProfile.objects.get(mobile_no=mobile_no)
        except CustomUserProfile.DoesNotExist:
            return Response({"status": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Check OTP validity
        if user_profile.otp != otp:
            return Response({"status": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            
        if timezone.now() > user_profile.otp_expiry:
            return Response({"status": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST)

        # Update password
        user = user_profile.user
        user.set_password(new_password)
        user.save()

        # Clear OTP fields
        user_profile.otp = None
        user_profile.otp_expiry = None
        user_profile.save()

        return Response({
            "status": "Password reset successful now login with your new password",
           }, status=status.HTTP_200_OK)