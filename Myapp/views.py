import logging
from django.http import JsonResponse
from django.views import View
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from .models import COIFormData, CustomUser, EmailVerification,CompanyEmail,StripePayment
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from .forms import PhoneForm, OTPForm
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status, permissions
from .serializers import CustomUserSerializer, StripePaymentSerializer
# from django.contrib.auth.models import User
from django.contrib.auth import get_user_model

from django.contrib.auth import authenticate
from django.core.cache import cache
from rest_framework import generics, status
import json
import random
import jwt
import requests
import datetime
import stripe
import os
import pandas as pd
from .models import VimeoVideo
from .utils import fetch_public_vimeo_video, fetch_unlisted_vimeo_video

# LinkedIn API configuration (unchanged)
LINKEDIN_CLIENT_ID = '86ym363ssaf6tz'
LINKEDIN_CLIENT_SECRET = 'WPL_AP1.P9uxAiGWy4DjSRYh.WIbjkw=='
LINKEDIN_REDIRECT_URI = 'http://127.0.0.1:8000/Myapp/linkedin-callback'
LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
LINKEDIN_PROFILE_URL = "https://api.linkedin.com/v2/me"

# Default redirect URL - fallback if setting is not defined
DEFAULT_REDIRECT_URL = getattr(settings, 'DEFAULT_REDIRECT_URL', '/')
stripe.api_key = 'sk_test_51RPvxVGq7lR7zc6NS93Kbg2HGhe1rK273sM4CIV7YcM44mcYOoQfprlLh3xbxsXbXxVRdAAhWEPnSrf9jPyQcZus00GzpVgzwB'
# Secret key for JWT
token_secret = settings.SECRET_KEY

User = get_user_model()

def generate_token(payload):
    return jwt.encode(payload, token_secret, algorithm="HS256")

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
def generate_username():
    colors = ['Red', 'Blue', 'Green', 'Yellow', 'Purple', 'Orange', 'Pink', 'Black', 'White', 'Gray']
    objects = ['Tiger', 'Rocket', 'Pencil', 'Laptop', 'Ball', 'Mountain', 'River', 'Car', 'Cloud', 'Phone']

    while True:
        color = random.choice(colors)
        obj = random.choice(objects)
        number = random.randint(0, 999)
        username = f"{color}{obj}{number:03}"

        if not User.objects.filter(username=username).exists():
            return username

@csrf_exempt
def send_email_otp(request):
    """
    Send OTP to user's email for verification
    """
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "Only POST method allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            return JsonResponse({"status": "error", "message": "Email is required"}, status=400)
        
        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({
                "status": "error",
                "message": "Invalid email format"
            }, status=400)
        
        # Check if user exists
        try:
            user = CustomUser.objects.get(email=email)
            
            # If email already verified
            if user.email_verified:
                return JsonResponse({
                    "status": "error",
                    "message": "Email already verified. Please login.",
                    "is_verified": True
                }, status=400)
            
            # Generate and save OTP
            otp = str(random.randint(100000, 999999))
            user.email_otp = otp
            user.otp_created_at = timezone.now()
            user.save()
            
        except CustomUser.DoesNotExist:
            return JsonResponse({
                "status": "error",
                "message": "User not found. Please register first.",
                "user_exists": False
            }, status=400)
        
        # Send email with OTP
        subject = 'Your OTP Code for Email Verification'
        message = f'Hello, \n\n Thank you for registering with us. To complete your email verification, please use the following One-Time Password (OTP): \n\n Your OTP code is: {otp}\n\nThis code is valid for the next 10 minutes. Please do not share this code with anyone.\n\n If you did not request this, please ignore this email. \n\n Best regards,\n Your Company Name \n ExitElivate.'
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)
        
        return JsonResponse({
            "status": "success",
            "message": "OTP sent successfully to your email"
        })
        
    except json.JSONDecodeError:
        return JsonResponse({"status": "error", "message": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Error: {str(e)}"}, status=500)

@csrf_exempt
def verify_email_otp(request):
    """
    Verify the OTP sent to email
    """
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "Only POST method allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email')
        otp_submitted = data.get('otp')
        
        if not email or not otp_submitted:
            return JsonResponse({"status": "error", "message": "Email and OTP required"}, status=400)
            
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({"status": "error", "message": "User not found"}, status=400)

        if user.is_otp_expired():
            return JsonResponse({"status": "error", "message": "OTP expired. Please request a new one."}, status=400)

        # Compare OTPs
        if str(user.email_otp) == str(otp_submitted):
            # OTP valid - mark email as verified
            user.email_verified = True
            user.email_otp = None  # Clear OTP
            user.otp_created_at = None
            user.save()
            
            return JsonResponse({
                "status": "success", 
                "message": "Email verified successfully.",
                "is_verified": True
            })
        else:
            return JsonResponse({"status": "error", "message": "Invalid OTP"}, status=400)
            
    except json.JSONDecodeError:
        return JsonResponse({"status": "error", "message": "Invalid JSON format"}, status=400)
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Server error: {str(e)}"}, status=500)

@csrf_exempt
def register(request):
    """
    Registration endpoint - creates user with email_verified=False and returns tokens
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body) if request.body else request.POST
            
            email = data.get('email')
            password = data.get('password')
            full_name = data.get('full_name')
            phone_number = data.get('phone_number')
            website_name = data.get('website_name')
            linkedin_token = data.get('linkedin_token', '')
            no_linkedin = data.get('no_linkedin', 'false') == 'true'

            try:
                coi_entry = COIFormData.objects.get(email=email)
                coi_entry.delete()
            except COIFormData.DoesNotExist:
                pass  # Entry doesn't exist, continue normally

            # Check required fields
            if not email or not password or not full_name:
                return JsonResponse({
                    "status": "error",
                    "message": "Email, password, and full name are required"
                }, status=400)
            
            # Check if user already exists
            if CustomUser.objects.filter(email=email).exists():
                return JsonResponse({
                    "status": "error",
                    "message": "User with this email already exists",
                    "user_exists": True
                }, status=400)
            
            # LinkedIn URL handling (optional)
            linkedin_url = None
            if linkedin_token and not no_linkedin:
                try:
                    # Verify LinkedIn token if provided
                    payload = jwt.decode(linkedin_token, token_secret, algorithms=["HS256"])
                    linkedin_id = payload.get('linkedin_id')
                    if linkedin_id:
                        linkedin_url = f"https://www.linkedin.com/in/{linkedin_id}"
                except jwt.InvalidTokenError:
                    return JsonResponse({
                        "status": "error",
                        "message": "Invalid LinkedIn verification token"
                    }, status=400)
            
            try:
                # Create the user with email_verified=False
                user = CustomUser.objects.create_user(
                    email=email,
                    password=password,
                    full_name=full_name,
                    phone_number=phone_number,
                    website_name=website_name,
                    linkedin_url=linkedin_url,
                    no_linkedin=no_linkedin,
                    email_verified=False  # Set to False initially
                )
                
                # Generate tokens exactly like in login
                tokens = get_tokens_for_user(user)
                
                return JsonResponse({
                    'status': 'success',
                    'message': 'Registration successful! Please verify your email.',
                    'tokens': tokens
                }, status=201)
                
            except Exception as e:
                return JsonResponse({
                    "status": "error",
                    "message": f"Registration failed: {str(e)}"
                }, status=400)
                
        except json.JSONDecodeError:
            return JsonResponse({
                "status": "error",
                "message": "Invalid JSON format"
            }, status=400)
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": f"Server error: {str(e)}"
            }, status=500)
    else:
        return JsonResponse({
            "status": "error",
            "message": "Only POST requests allowed"
        }, status=405)

@csrf_exempt
def login_view(request):
    """
    Login endpoint - unchanged but now relies on CustomUser model only
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body) if request.body else request.POST
            identifier = data.get('identifier')  # username or email
            password = data.get('password')

            if not identifier or not password:
                return JsonResponse({'status': 'error', 'message': 'Username/email and password required'}, status=400)

            user = authenticate(request, username=identifier, password=password)

            if user is not None:
                tokens = get_tokens_for_user(user)
                return JsonResponse({
                    'status': 'success',
                    'message': 'Login successful',
                    'tokens': tokens
                }, status=200)
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid credentials'}, status=401)

        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON format'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Server error: {str(e)}'
            }, status=500)

    return JsonResponse({'status': 'error', 'message': 'Only POST method allowed'}, status=405)

@csrf_exempt
def check_email_status(request):
    """
    Check if an email is registered and verified
    """
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "Only POST method allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            return JsonResponse({"status": "error", "message": "Email is required"}, status=400)
        
        try:
            user = CustomUser.objects.get(email=email)
            return JsonResponse({
                "status": "success", 
                "user_exists": True,
                "email_verified": user.email_verified,
                "message": "Email already registered. Please login." if user.email_verified else "Email registered but not verified."
            })
        except CustomUser.DoesNotExist:
            return JsonResponse({
                "status": "success", 
                "user_exists": False,
                "email_verified": False,
                "message": "Email not registered."
            })
            
    except json.JSONDecodeError:
        return JsonResponse({"status": "error", "message": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)

# Keeping the LinkedIn verification code unchanged...

class LinkedInAuthView(View):
    def get(self, request):
        # Get the redirect URL from query params or use default
        redirect_url = request.GET.get("redirect_url", DEFAULT_REDIRECT_URL)
        
        # Check if the user indicates they don't have LinkedIn
        if request.GET.get("no_linkedin"):
            return redirect(f"{redirect_url}?linkedin_verified=true")

        # Store the redirect URL in session for the callback
        request.session['linkedin_redirect_url'] = redirect_url
        
        # Generate LinkedIn OAuth URL
        auth_url = f"{LINKEDIN_AUTH_URL}?response_type=code&client_id={LINKEDIN_CLIENT_ID}&redirect_uri={LINKEDIN_REDIRECT_URI}&scope=r_liteprofile%20r_emailaddress"
        return redirect(auth_url)

class LinkedInCallbackView(View):
    def get(self, request):
        # Get redirect URL from session or use default
        redirect_url = request.session.get('linkedin_redirect_url', DEFAULT_REDIRECT_URL)
        
        code = request.GET.get("code")
        if not code:
            error_message = "Authorization code not found."
            return redirect(f"{redirect_url}?linkedin_error={error_message}")

        try:
            # Exchange code for access token
            token_response = requests.post(LINKEDIN_TOKEN_URL, data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": LINKEDIN_REDIRECT_URI,
                "client_id": LINKEDIN_CLIENT_ID,
                "client_secret": LINKEDIN_CLIENT_SECRET,
            })
            token_data = token_response.json()
            
            if 'error' in token_data:
                error_message = token_data.get('error_description', token_data.get('error', 'Unknown error'))
                return redirect(f"{redirect_url}?linkedin_error={error_message}")
                
            access_token = token_data.get("access_token")
            if not access_token:
                return redirect(f"{redirect_url}?linkedin_error=Failed to obtain access token")

            # Fetch LinkedIn profile data
            profile_response = requests.get(LINKEDIN_PROFILE_URL, headers={
                "Authorization": f"Bearer {access_token}"
            })
            profile_data = profile_response.json()

            if profile_response.status_code != 200:
                return redirect(f"{redirect_url}?linkedin_error=Failed to fetch profile data")

            # Generate JWT token for verification
            payload = {
                "linkedin_id": profile_data.get("id"),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            jwt_token = generate_token(payload)

            # Redirect back to client with the token
            return redirect(f"{redirect_url}?linkedin_token={jwt_token}")

        except Exception as e:
            error_message = f"Error during LinkedIn verification: {str(e)}"
            return redirect(f"{redirect_url}?linkedin_error={error_message}")

#group chat
@login_required(login_url='login')
def room(request):
    return render(request, 'chat/room.html', {
        'username': request.user.username,
        'user_is_authenticated': request.user.is_authenticated,
    })

@login_required(login_url='login')
def ai_chatbox(request):
    messages = [
        {"sender": "user", "text": "Hi!"},
        {"sender": "ai", "text": "Hello! How can I help you today?"},
        {"sender": "user", "text": "What is your name?"},
        {"sender": "ai", "text": "I’m your AI Assistant."}
    ]
    return render(request, "chat/ai_chatbox.html", {
        "messages": messages,
        'username': request.user.username,
        'user_is_authenticated': request.user.is_authenticated,
    })

@login_required(login_url='login')
def user_logout(request):
    logout(request)
    return redirect('login')

#settings

class SettingsSectionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sections = [
            {"key": "personal_information", "label": "Personal Information"},
            {"key": "change_username", "label": "Change Username"},
            {"key": "change_email", "label": "Change Email ID"},
            {"key": "change_password", "label": "Change Password"},
        ]
        return Response({"sections": sections})

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = request.user  # current logged in user instance
        serializer = CustomUserSerializer(profile)
        data = serializer.data
        data['username'] = profile.username  # add username for frontend display
        return Response(data)

    def put(self, request):
        """
        Update user profile with password verification
        """
        try:
            profile = request.user
            password = request.data.get('password')
            
            # Verify password first
            if not password:
                return Response({
                    "status": "error", 
                    "message": "Password is required for profile updates."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if provided password is correct
            if not profile.check_password(password):
                return Response({
                    "status": "error", 
                    "message": "Invalid password. Please try again."
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Remove password from data before serialization
            update_data = request.data.copy()
            update_data.pop('password', None)
            
            # Update profile
            serializer = CustomUserSerializer(profile, data=update_data, partial=True)
            if serializer.is_valid():
                serializer.save()
                
                logger.info(f"Profile updated successfully for user: {profile.email}")
                
                return Response({
                    "status": "success",
                    "message": "Profile updated successfully.",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "status": "error",
                    "message": "Invalid data provided.",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error updating profile for user {request.user.email}: {str(e)}")
            return Response({
                "status": "error",
                "message": "An error occurred while updating profile. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangeUsernameView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        username_color = request.data.get('username_color')
        username_object = request.data.get('username_object')
        username_num = request.data.get('username_num')
        new_username = f"{username_color}{username_object}{username_num}"

        password = request.data.get('password')

        if not new_username or not password:
            return Response({"error": "New username and password required."},
                            status=status.HTTP_400_BAD_REQUEST)

        if not request.user.check_password(password):
            return Response({"error": "Password incorrect."},
                    status=status.HTTP_401_UNAUTHORIZED)


        if User.objects.filter(username=new_username).exists():
            return Response({"error": "Username already taken."},
                            status=status.HTTP_400_BAD_REQUEST)

        request.user.username = new_username
        request.user.save()
        return Response({"message": "Username updated successfully."})

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            logger.info(f"Password change request from user: {request.user.email}")
            
            user = request.user
            current_password = request.data.get("current_password")
            new_password = request.data.get("new_password")

            # Validate required fields
            if not current_password:
                return Response({
                    "error": "Current password is required."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not new_password:
                return Response({
                    "error": "New password is required."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate password length
            if len(new_password) < 6:
                return Response({
                    "error": "New password must be at least 6 characters long."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if current password is correct
            if not user.check_password(current_password):
                logger.warning(f"Invalid current password attempt for user: {user.email}")
                return Response({
                    "error": "Current password is incorrect."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if new password is different from current password
            if user.check_password(new_password):
                return Response({
                    "error": "New password must be different from current password."
                }, status=status.HTTP_400_BAD_REQUEST)

            # Update password
            user.set_password(new_password)
            user.save()
            
            logger.info(f"Password successfully changed for user: {user.email}")
            
            return Response({
                "message": "Password updated successfully."
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error changing password for user {request.user.email}: {str(e)}")
            return Response({
                "error": "An error occurred while changing password. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ForgotPasswordSendOTP(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        otp = random.randint(100000, 999999)
        cache.set(f"otp_{email}", otp, timeout=600)  # 5 minutes

        send_mail(
            subject="Your OTP Code",
            message=f"Your OTP code is: {otp}",
            from_email="noreply@example.com",
            recipient_list=[email],
        )

        return Response({"message": "OTP sent to email."}, status=status.HTTP_200_OK)

class VerifyOTP(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({"error": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        cached_otp = cache.get(f"otp_{email}")
        if str(cached_otp) != str(otp):
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        cache.set(f"otp_verified_{email}", True, timeout=600)  # Allow password reset for 10 minutes

        return Response({"message": "OTP verified successfully."})

class ResetPassword(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')

        if not email or not new_password:
            return Response({"error": "Email and new password required."}, status=status.HTTP_400_BAD_REQUEST)

        verified = cache.get(f"otp_verified_{email}")
        if not verified:
            return Response({"error": "OTP not verified or session expired."}, status=status.HTTP_403_FORBIDDEN)

        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            cache.delete(f"otp_verified_{email}")
            return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)

class SendEmailOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        email = request.data.get("email")
        user = request.user
        
        if not email:
            return Response({"error": "Email is required."}, status=400)
        
        # Check if email already exists for this user
        if CompanyEmail.objects.filter(user=user, email=email).exists():
            return Response({"error": "Email already exists for this user."}, status=400)
        
        # Check if email is already used by another user
        if User.objects.filter(email=email).exists() and user.email != email:
            return Response({"error": "Email is already in use by another account."}, status=400)
        
        # Generate OTP
        otp = random.randint(100000, 999999)
        cache.set(f"email_otp_{email}_{user.id}", otp, timeout=600)  # 10 minutes
        
        # Send OTP via email
        try:
            send_mail(
                "Verify Your Email",
                f"Your verification code is {otp}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False
            )
            return Response({"message": "OTP sent to email."})
        except Exception as e:
            return Response({"error": "Failed to send OTP. Please try again."}, status=500)

class VerifyEmailOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        user = request.user

        if not email or not otp:
            return Response({"error": "Email and OTP are required."}, status=400)

        # Check cached OTP with user-specific key
        cached_otp = cache.get(f"email_otp_{email}_{user.id}")
        if not cached_otp or str(cached_otp) != str(otp):
            return Response({"error": "Invalid or expired OTP."}, status=400)

        # Create or update CompanyEmail only after successful verification
        try:
            # Ensure primary email exists
            if user.email and not CompanyEmail.objects.filter(user=user, email=user.email).exists():
                CompanyEmail.objects.create(
                    user=user,
                    email=user.email,
                    is_primary=True,
                    verified=True
                )
            
            # Create the new verified email
            company_email, created = CompanyEmail.objects.get_or_create(
                user=user,
                email=email,
                defaults={'verified': True, 'is_primary': False}
            )
            
            if not created:
                company_email.verified = True
                company_email.save()
            
            # Clear the OTP from cache
            cache.delete(f"email_otp_{email}_{user.id}")
            
            return Response({
                "message": "Email verified and added successfully.",
                "email": company_email.email,
                "verified": company_email.verified
            })
            
        except Exception as e:
            return Response({"error": "Failed to save email. Please try again."}, status=500)

class ListCompanyEmailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        emails = request.user.company_emails.all()
        return Response([
            {"email": e.email, "verified": e.verified} for e in emails
        ])

class SetPrimaryEmailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        email_id = request.data.get("email")
        password = request.data.get("password")
        user = request.user

        if not email_id or not password:
            return Response({"error": "Email and password are required."}, status=400)

        authenticated_user = authenticate(username=user.email, password=password)
        if authenticated_user is None:
            return Response({"error": "Invalid password."}, status=401)

        try:
            email_record = CompanyEmail.objects.get(user=user, email=email_id)
        except CompanyEmail.DoesNotExist:
            return Response({"error": "Email not found for this user."}, status=404)

        CompanyEmail.objects.filter(user=user).update(is_primary=False)

        email_record.is_primary = True
        email_record.save()

        user.email = email_id
        user.save()

        return Response({"message": f"{email_id} set as primary email and updated in user profile."}, status=200)

class RemoveEmailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        email_id = request.data.get("email")
        password = request.data.get("password")
        user = request.user

        if not email_id or not password:
            return Response({"error": "Email and password are required."}, status=400)

        authenticated_user = authenticate(username=user.email, password=password)
        if authenticated_user is None:
            return Response({"error": "Invalid password."}, status=401)

        try:
            email_record = CompanyEmail.objects.get(user=user, email=email_id)
        except CompanyEmail.DoesNotExist:
            return Response({"error": "Email not found for this user."}, status=404)

        deleted, _ = CompanyEmail.objects.filter(user=request.user, email=email_id).delete()

        return Response({"message": f"{email_id} remove successfully."}, status=200)

class SuccessfulPaymentsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        payments = StripePayment.objects.filter(user=request.user, status__iexact="Success")
        serializer = StripePaymentSerializer(payments, many=True)
        return Response(serializer.data)

class RefundPaymentsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        payments = StripePayment.objects.filter(user=request.user, status__iexact="refund")
        serializer = StripePaymentSerializer(payments, many=True)
        return Response(serializer.data)

@csrf_exempt
def read_excel_sheet_by_name(request):
    excel_path = os.path.join(settings.BASE_DIR, 'media', 'uploads', 'Statistics.xlsx')

    try:
        filter_category = request.GET.get('category', None)

        df = pd.read_excel(excel_path, sheet_name="Categories of statistics", engine='openpyxl')

        df['Research Topic'] = df['Research Topic'].ffill()
        df = df[df['Statistics'].notna() & (df['Statistics'].str.strip() != '')]

        if filter_category:
            df = df[df['Master Category'] == filter_category]

        result = []

        for category, cat_group in df.groupby('Master Category'):

            research_points = []
            for topic, topic_group in cat_group.groupby('Research Topic'):
                stats_list = []
                for _, row in topic_group.iterrows():
                    stat_text = row['Statistics'].strip()
                    stat_url = row['URL Link'] if 'URL Link' in row and pd.notna(row['URL Link']) else ""
                    stats_list.append({
                        "context": stat_text,
                        "url": stat_url
                    })

                research_points.append({
                    "name": topic,
                    "statistics": stats_list
                })

            result.append({
                "category": category,
                "research_points": research_points
            })

        return JsonResponse(result, safe=False)

    except Exception as e:
        return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)

@csrf_exempt
def get_category_list(request):
    excel_path = os.path.join(settings.BASE_DIR, 'media', 'uploads', 'Statistics.xlsx')

    try:
        df = pd.read_excel(excel_path, sheet_name="Categories of statistics", engine='openpyxl')

        if 'Master Category' not in df.columns:
            return JsonResponse({'error': "'Master Category' column not found in Excel sheet."}, status=400)

        categories = df['Master Category'].ffill().dropna().unique().tolist()

        return JsonResponse(categories, safe=False)

    except Exception as e:
        return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)

#payment
class CreateCheckoutSessionView(APIView):
    def post(self, request):
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'unit_amount': int(float(request.data['amount']) * 100),  # amount in cents
                        'product_data': {
                            'name': request.data['product_name'],
                        },
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=f"{settings.DOMAIN_URL}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{settings.DOMAIN_URL}/payment-cancelled",
            )
            return Response({'sessionId': checkout_session.id})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)



@method_decorator(csrf_exempt, name='dispatch')
class StripeWebhookView(APIView):
    def post(self, request):
        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
        endpoint_secret = 'your_webhook_secret_here'

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        except stripe.error.SignatureVerificationError:
            return HttpResponse(status=400)

        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']

            StripePayment.objects.create(
                stripe_session_id=session['id'],
                email=session.get('customer_email', ''),
                amount=int(session['amount_total']) / 100,
                currency=session['currency'],
                status=session['payment_status']
            )

        return HttpResponse(status=200)
logger = logging.getLogger(__name__)
class ExtractUserDataFromHeaderView(APIView):
    """
    Extract user data from JWT token in Authorization header
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            logger.info(f"ExtractUserDataFromHeaderView called by user: {request.user}")
            
            # Check if user is authenticated
            if not request.user or not request.user.is_authenticated:
                logger.warning("User is not authenticated")
                return Response({
                    "status": "error",
                    "message": "User not authenticated"
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            user = request.user
            logger.info(f"Authenticated user: {user.email if hasattr(user, 'email') else 'No email'}")
            
            # Check if CustomUserSerializer exists and works
            try:
                serializer = CustomUserSerializer(user)
                user_data = serializer.data
                logger.info("Serialization successful")
            except Exception as serializer_error:
                logger.error(f"Serialization error: {str(serializer_error)}")
                # Fallback: manual serialization
                user_data = {
                    'id': user.id,
                    'email': getattr(user, 'email', ''),
                    'full_name': getattr(user, 'full_name', ''),
                    'phone_number': getattr(user, 'phone_number', ''),
                    'website_name': getattr(user, 'website_name', ''),
                    'linkedin_url': getattr(user, 'linkedin_url', ''),
                    'no_linkedin': getattr(user, 'no_linkedin', False),
                    'email_verified': getattr(user, 'email_verified', False),
                }
            
            # Add additional fields safely
            additional_data = {}
            
            # Safely add username
            if hasattr(user, 'username'):
                additional_data['username'] = user.username
            
            # Safely add is_active
            if hasattr(user, 'is_active'):
                additional_data['is_active'] = user.is_active
            
            # Safely add date_joined
            if hasattr(user, 'date_joined') and user.date_joined:
                try:
                    additional_data['date_joined'] = user.date_joined.isoformat()
                except Exception as date_error:
                    logger.warning(f"Error formatting date_joined: {str(date_error)}")
                    additional_data['date_joined'] = str(user.date_joined)
            
            # Safely add last_login
            if hasattr(user, 'last_login') and user.last_login:
                try:
                    additional_data['last_login'] = user.last_login.isoformat()
                except Exception as date_error:
                    logger.warning(f"Error formatting last_login: {str(date_error)}")
                    additional_data['last_login'] = str(user.last_login)
            
            # Merge additional data
            user_data.update(additional_data)
            
            logger.info("User data prepared successfully")
            
            return Response({
                "status": "success",
                "message": "User data extracted successfully",
                "user_data": user_data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Unexpected error in ExtractUserDataFromHeaderView: {str(e)}", exc_info=True)
            return Response({
                "status": "error", 
                "message": f"Server error: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class CreateCheckoutSessionView(APIView):
    """
    Create a Stripe Checkout Session for payment processing
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            # Get data from request
            amount = request.data.get('amount', 2999)  # Default $29.99
            product_name = request.data.get('product_name', 'Premium Plan')
            billing_info = request.data.get('billing_info', {})
            
            # Validate required fields
            if not billing_info.get('fullName') or not billing_info.get('email'):
                return Response({
                    'error': 'Full name and email are required in billing_info'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create the checkout session
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                customer_email=billing_info.get('email'),
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'unit_amount': int(amount),  # amount in cents
                        'product_data': {
                            'name': product_name,
                            'description': f'Premium plan for {billing_info.get("fullName")}',
                        },
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}",
                cancel_url=f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}/payment-cancelled",
                metadata={
                    'user_id': str(request.user.id),
                    'user_email': request.user.email,
                    'customer_name': billing_info.get('fullName'),
                    'company_name': billing_info.get('companyName', ''),
                }
            )
            
            # Create payment record in database
            StripePayment.objects.create(
                user=request.user,
                stripe_session_id=checkout_session.id,
                email=billing_info.get('email'),
                amount=float(amount) / 100,  # Convert cents to dollars
                currency='usd',
                status='pending',
                customer_name=billing_info.get('fullName'),
                company_name=billing_info.get('companyName', ''),
                product_name=product_name
            )
            
            logger.info(f"Checkout session created: {checkout_session.id} for user: {request.user.id}")
            
            return Response({
                'sessionId': checkout_session.id,
                'url': checkout_session.url
            })
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error: {str(e)}")
            return Response({
                'error': f'Payment processing error: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Unexpected error creating checkout session: {str(e)}")
            return Response({
                'error': 'An unexpected error occurred while processing your payment request.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class StripeWebhookView(View):
    """
    Handle Stripe webhook events
    """
    
    def post(self, request):
        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
        endpoint_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', '')
        
        if not endpoint_secret:
            logger.error("Stripe webhook secret not configured")
            return HttpResponse(status=400)

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        except ValueError as e:
            logger.error(f"Invalid payload: {e}")
            return HttpResponse(status=400)
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid signature: {e}")
            return HttpResponse(status=400)

        # Handle the event
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            self.handle_checkout_session_completed(session)
            
        elif event['type'] == 'payment_intent.succeeded':
            payment_intent = event['data']['object']
            self.handle_payment_intent_succeeded(payment_intent)
            
        elif event['type'] == 'payment_intent.payment_failed':
            payment_intent = event['data']['object']
            self.handle_payment_intent_failed(payment_intent)
        
        else:
            logger.info(f"Unhandled event type: {event['type']}")

        return HttpResponse(status=200)
    
    def handle_checkout_session_completed(self, session):
        """Handle successful checkout session completion"""
        try:
            # Update payment record
            payment = StripePayment.objects.get(stripe_session_id=session['id'])
            payment.status = 'completed'
            payment.stripe_payment_intent_id = session.get('payment_intent')
            payment.save()
            
            logger.info(f"Payment completed for session: {session['id']}")
            
            # Here you can add additional logic like:
            # - Send confirmation email to customer
            # - Activate user's premium features
            # - Update user's subscription status
            
        except StripePayment.DoesNotExist:
            logger.error(f"Payment record not found for session: {session['id']}")
        except Exception as e:
            logger.error(f"Error handling checkout session completed: {str(e)}")
    
    def handle_payment_intent_succeeded(self, payment_intent):
        """Handle successful payment intent"""
        try:
            # Find payment by payment intent ID
            payment = StripePayment.objects.get(
                stripe_payment_intent_id=payment_intent['id']
            )
            payment.status = 'succeeded'
            payment.save()

            user = payment.user
            user.paid = True
            user.save()

            
            logger.info(f"Payment intent succeeded: {payment_intent['id']}")
            
        except StripePayment.DoesNotExist:
            logger.warning(f"Payment record not found for payment intent: {payment_intent['id']}")
        except Exception as e:
            logger.error(f"Error handling payment intent succeeded: {str(e)}")
    
    def handle_payment_intent_failed(self, payment_intent):
        """Handle failed payment intent"""
        try:
            # Find payment by payment intent ID
            payment = StripePayment.objects.get(
                stripe_payment_intent_id=payment_intent['id']
            )
            payment.status = 'failed'
            payment.save()

            user = payment.user
            user.paid = False
            user.save()
            
            logger.info(f"Payment intent failed: {payment_intent['id']}")
            
        except StripePayment.DoesNotExist:
            logger.warning(f"Payment record not found for payment intent: {payment_intent['id']}")
        except Exception as e:
            logger.error(f"Error handling payment intent failed: {str(e)}")


class PaymentStatusView(APIView):
    """
    Check payment status for a specific session
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        session_id = request.query_params.get('session_id')
        
        if not session_id:
            return Response({
                'error': 'session_id parameter is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Retrieve session from Stripe
            session = stripe.checkout.Session.retrieve(session_id)
            
            # Get payment record from database
            try:
                payment = StripePayment.objects.get(
                    stripe_session_id=session_id,
                    user=request.user
                )
                
                return Response({
                    'status': session.payment_status,
                    'amount_total': session.amount_total,
                    'currency': session.currency,
                    'customer_email': session.customer_email,
                    'payment_status': payment.status,
                    'created_at': payment.created_at.isoformat() if payment.created_at else None
                })
                
            except StripePayment.DoesNotExist:
                return Response({
                    'error': 'Payment record not found'
                }, status=status.HTTP_404_NOT_FOUND)
                
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error retrieving session: {str(e)}")
            return Response({
                'error': 'Error retrieving payment status'
            }, status=status.HTTP_400_BAD_REQUEST)


class UserPaymentsView(APIView):
    """
    Get all payments for the authenticated user
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        payments = StripePayment.objects.filter(user=request.user).order_by('-created_at')
        
        payment_data = []
        for payment in payments:
            payment_data.append({
                'id': payment.id,
                'amount': payment.amount,
                'currency': payment.currency,
                'status': payment.status,
                'product_name': payment.product_name,
                'customer_name': payment.customer_name,
                'company_name': payment.company_name,
                'created_at': payment.created_at.isoformat() if payment.created_at else None,
                'stripe_session_id': payment.stripe_session_id
            })
        
        return Response({
            'payments': payment_data
        })
    
class FetchPublicVideoView(APIView):
    def get(self, request, video_id):
        video = fetch_public_vimeo_video(video_id)
        if "error" in video:
            return Response({"error": video["error"]}, status=400)
        # Save video URL to the database
        VimeoVideo.objects.update_or_create(
            video_id=video_id, defaults={"video_url": video["video_url"], "is_public": True}
        )
        return Response(video)

class FetchUnlistedVideoView(APIView):
    def get(self, request, video_id):
        video = fetch_unlisted_vimeo_video(video_id)
        if "error" in video:
            return Response({"error": video["error"]}, status=400)
        # Save video URL to the database
        VimeoVideo.objects.update_or_create(
            video_id=video_id, defaults={"video_url": video["video_url"], "is_public": False}
        )
        return Response(video)
    
@csrf_exempt
def save_coi_form(request):
    """Save COI form data when user clicks submit button"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body) if request.body else request.POST
            
            email = data.get('email')
            full_name = data.get('full_name')
            phone_number = data.get('phone_number')
            website_name = data.get('website_name', '')
            
            # Check required fields
            if not email or not full_name or not phone_number:
                return JsonResponse({
                    "status": "error",
                    "message": "Email, full name, and phone number are required"
                }, status=400)
            
            # Save or update COI form data
            coi_data, created = COIFormData.objects.update_or_create(
                email=email,
                defaults={
                    'full_name': full_name,
                    'phone_number': phone_number,
                    'website_name': website_name
                }
            )
            
            return JsonResponse({
                'status': 'success',
                'message': 'Form data saved successfully',
                'created': created
            }, status=200)
            
        except json.JSONDecodeError:
            return JsonResponse({
                "status": "error",
                "message": "Invalid JSON format"
            }, status=400)
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": f"Server error: {str(e)}"
            }, status=500)
    else:
        return JsonResponse({
            "status": "error",
            "message": "Only POST requests allowed"
        }, status=405)