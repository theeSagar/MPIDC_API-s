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
                {"status": f"Missing required fields: {', '.join(missing_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if len(mobile_no) != 12:
            return Response({
                "status": "Mobile number must be exactly 12 digits."
            }, status=status.HTTP_400_BAD_REQUEST)

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
                {
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
            {"status":"Validation failed", "errors": formatted_errors},
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


        

        