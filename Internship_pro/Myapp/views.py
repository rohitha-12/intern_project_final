from django.http import JsonResponse
from django.views import View
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from .models import CustomUser, EmailVerification, UserProfile,CompanyEmail,StripePayment
from django.views.decorators.csrf import csrf_exempt
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
from rest_framework import status
from .serializers import UserProfileSerializer, StripePaymentSerializer
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
# LinkedIn API configuration (unchanged)
LINKEDIN_CLIENT_ID = '86ym363ssaf6tz'
LINKEDIN_CLIENT_SECRET = 'WPL_AP1.P9uxAiGWy4DjSRYh.WIbjkw=='
LINKEDIN_REDIRECT_URI = 'http://127.0.0.1:8000/Myapp/linkedin-callback'
LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
LINKEDIN_PROFILE_URL = "https://api.linkedin.com/v2/me"

# Default redirect URL - fallback if setting is not defined
DEFAULT_REDIRECT_URL = getattr(settings, 'DEFAULT_REDIRECT_URL', '/')

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

@csrf_exempt
def send_email_otp(request):
    """
    Endpoint to send OTP to an email address for verification
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
        
        # Check if user already exists in CustomUser table
        try:
            user = CustomUser.objects.get(email=email)
            return JsonResponse({
                "status": "error",
                "message": "Email already registered. Please login.",
                "is_registered": True
            }, status=400)
        except CustomUser.DoesNotExist:
            # Continue with OTP process for new email
            pass
        
        # Check EmailVerification table
        try:
            email_verification = EmailVerification.objects.get(email=email)
            
            # Check if already verified and registered
            if email_verification.is_verified and email_verification.is_registered:
                return JsonResponse({
                    "status": "error",
                    "message": "Email already registered. Please login.",
                    "is_registered": True
                }, status=400)
                
            # Check if verified but not registered
            if email_verification.is_verified and not email_verification.is_registered:
                return JsonResponse({
                    "status": "success",
                    "message": "Email already verified. You can complete registration.",
                    "is_verified": True,
                    "is_registered": False
                })
                
            # Email exists but not verified - send a new OTP
            otp = str(random.randint(100000, 999999))
            email_verification.otp = otp
            email_verification.created_at = timezone.now()
            email_verification.save()
        
        except EmailVerification.DoesNotExist:
            # New email - create record and send OTP
            otp = str(random.randint(100000, 999999))
            EmailVerification.objects.create(
                email=email,
                otp=otp,
                is_verified=False,
                is_registered=False
            )
        
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
    Endpoint to verify the OTP sent to email
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
            email_verification = EmailVerification.objects.get(email=email)
        except EmailVerification.DoesNotExist:
            return JsonResponse({"status": "error", "message": "OTP not sent for this email"}, status=400)

        if email_verification.is_expired():
            return JsonResponse({"status": "error", "message": "OTP expired. Please request a new one."}, status=400)

        # Compare OTPs as strings
        if str(email_verification.otp) == str(otp_submitted):
            # OTP valid - update verification status
            email_verification.is_verified = True
            email_verification.save()
            
            return JsonResponse({
                "status": "success", 
                "message": "Email verified successfully. You can now complete registration.",
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
    Registration endpoint that requires email verification first
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body) if request.body else request.POST
            
            email = data.get('email')
            username = data.get('username')
            password = data.get('password')
            full_name = data.get('full_name')
            phone_number = data.get('phone_number')
            linkedin_token = data.get('linkedin_token', '')
            no_linkedin = data.get('no_linkedin', 'false').lower() == 'true'

            # Check required fields
            if not email or not username or not password:
                return JsonResponse({
                    "status": "error",
                    "message": "Email, username, and password are required"
                }, status=400)
            
            # First check if user already exists in CustomUser table
            try:
                existing_user = CustomUser.objects.get(email=email)
                return JsonResponse({
                    "status": "error",
                    "message": "User with this email already exists",
                    "is_registered": True
                }, status=400)
            except CustomUser.DoesNotExist:
                # Continue with registration check
                pass
                
            # Check EmailVerification table to ensure email is verified
            try:
                email_verification = EmailVerification.objects.get(email=email)
                
                # Check if already registered
                if email_verification.is_registered:
                    return JsonResponse({
                        "status": "error",
                        "message": "Email already registered. Please login.",
                        "is_registered": True
                    }, status=400)
                
                # Check if verified
                if not email_verification.is_verified:
                    return JsonResponse({
                        "status": "error",
                        "message": "Email not verified. Please verify your email first.",
                        "is_verified": False
                    }, status=400)
                
                # Email is verified and not registered - proceed with registration
            except EmailVerification.DoesNotExist:
                return JsonResponse({
                    "status": "error",
                    "message": "Email not verified. Please verify your email first.",
                    "is_verified": False
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
                # Create the user
                user = CustomUser.objects.create_user(
                    email=email,
                    username=username,
                    password=password,
                    full_name=full_name,
                    phone_number=phone_number,
                    linkedin_url=linkedin_url,
                    no_linkedin=no_linkedin,
                    email_verified=True  # Email is already verified
                )
                
                # Update the EmailVerification record
                email_verification.is_registered = True
                email_verification.save()
                
                # Generate tokens for automatic login
                tokens = get_tokens_for_user(user)
                
                return JsonResponse({
                    "status": "success",
                    "message": "Registration successful!",
                    "is_registered": True,
                    "tokens": tokens
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
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                return JsonResponse({'status': 'error', 'message': 'Email and password required'}, status=400)

            user = authenticate(request, username=email, password=password)

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
                "status": "error",
                "message": "Invalid JSON format"
            }, status=400)
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": f"Server error: {str(e)}"
            }, status=500)

    return JsonResponse({'status': 'error', 'message': 'Only POST method allowed'}, status=405)

@csrf_exempt
def check_email_status(request):
    """
    Endpoint to check if an email is already verified or registered
    """
    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "Only POST method allowed"}, status=405)
    
    try:
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            return JsonResponse({"status": "error", "message": "Email is required"}, status=400)
        
        # First check CustomUser to see if already registered
        try:
            user = CustomUser.objects.get(email=email)
            return JsonResponse({
                "status": "success", 
                "is_registered": True,
                "message": "Email already registered. Please login."
            })
        except CustomUser.DoesNotExist:
            # Continue checking EmailVerification table
            pass
            
        # Check EmailVerification table
        try:
            email_verification = EmailVerification.objects.get(email=email)
            
            if email_verification.is_verified and email_verification.is_registered:
                return JsonResponse({
                    "status": "success", 
                    "is_registered": True,
                    "is_verified": True,
                    "message": "Email already registered. Please login."
                })
            elif email_verification.is_verified and not email_verification.is_registered:
                return JsonResponse({
                    "status": "success", 
                    "is_registered": False,
                    "is_verified": True,
                    "message": "Email verified. You can complete registration."
                })
            else:
                return JsonResponse({
                    "status": "success", 
                    "is_registered": False,
                    "is_verified": False,
                    "message": "Email not verified. Please verify your email."
                })
                
        except EmailVerification.DoesNotExist:
            # New email, never seen before
            return JsonResponse({
                "status": "success", 
                "is_registered": False,
                "is_verified": False,
                "message": "Email not verified. Please verify your email."
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
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        serializer = UserProfileSerializer(profile)
        data = serializer.data
        data['username'] = request.user.username  # add username for frontend display
        return Response(data)

    def put(self, request):
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChangeUsernameView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        new_username = request.data.get('new_username')
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
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not user.check_password(current_password):
            return Response({"error": "Current password is incorrect."}, status=400)

        user.set_password(new_password)
        user.save()
        return Response({"message": "Password updated successfully."})

class ForgotPasswordSendOTP(APIView):
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

        if user.email and not CompanyEmail.objects.filter(user=user, email=user.email).exists():
            CompanyEmail.objects.create(
                user=user,
                email=user.email,
                is_primary=True,
                verified=True  # assume verified since it's user.email
            )

        company_email_exists = CompanyEmail.objects.filter(user=user, email=email).exists()
        if not company_email_exists:

            # Add the new email
            CompanyEmail.objects.create(
                user=user,
                email=email,
                is_primary=False,
                verified=False
            )

        otp = random.randint(100000, 999999)
        cache.set(f"otp_{email}", otp, timeout=600)  # 10 minutes

        # Send OTP via email
        send_mail(
            "Verify Your Email",
            f"Your verification code is {otp}",
            "no-reply@example.com",
            [email]
        )

        return Response({"message": "OTP sent to email."})

class VerifyEmailOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        if not email or not otp:
            return Response({"error": "Email and OTP are required."}, status=400)

        cached_otp = cache.get(f"otp_{email}")
        if str(cached_otp) != str(otp):
            return Response({"error": "Invalid or expired OTP."}, status=400)

        company_email, created = CompanyEmail.objects.update_or_create(
            user=request.user,
            email=email,
            defaults={'verified': True}
        )

        return Response({
            "message": "Email verified and saved.",
            "email": company_email.email,
            "verified": company_email.verified
        })

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

