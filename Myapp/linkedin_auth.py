import os
import jwt
import json
import requests
import datetime
from django.conf import settings
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.shortcuts import redirect
from django.urls import reverse

# LinkedIn OAuth Configuration
LINKEDIN_CLIENT_ID = os.getenv('LINKEDIN_CLIENT_ID', 'your_linkedin_client_id')
LINKEDIN_CLIENT_SECRET = os.getenv('LINKEDIN_CLIENT_SECRET', 'your_linkedin_client_secret')
LINKEDIN_REDIRECT_URI = os.getenv('LINKEDIN_REDIRECT_URI', 'http://localhost:8000/auth/linkedin/callback/')
LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
LINKEDIN_PROFILE_URL = "https://api.linkedin.com/v2/people/~"
LINKEDIN_EMAIL_URL = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"

# JWT Secret for token generation
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', settings.SECRET_KEY)

class LinkedInAuthView(View):
    """
    Initiates LinkedIn OAuth flow
    """
    def get(self, request):
        # Get state parameter for security and redirect URL
        state = request.GET.get('state', '')
        redirect_url = request.GET.get('redirect_url', 'http://localhost:3000')
        
        # Store redirect URL in session for callback
        request.session['linkedin_redirect_url'] = redirect_url
        request.session['linkedin_state'] = state
        
        # Build LinkedIn authorization URL
        auth_params = {
            'response_type': 'code',
            'client_id': LINKEDIN_CLIENT_ID,
            'redirect_uri': LINKEDIN_REDIRECT_URI,
            'state': state,
            'scope': 'r_liteprofile r_emailaddress'
        }
        
        auth_url = f"{LINKEDIN_AUTH_URL}?" + "&".join([f"{k}={v}" for k, v in auth_params.items()])
        return redirect(auth_url)

class LinkedInCallbackView(View):
    """
    Handles LinkedIn OAuth callback and exchanges code for profile data
    """
    def get(self, request):
        # Get stored redirect URL and state
        redirect_url = request.session.get('linkedin_redirect_url', 'http://localhost:3000')
        stored_state = request.session.get('linkedin_state', '')
        
        # Verify state parameter
        returned_state = request.GET.get('state', '')
        code = request.GET.get('code')
        error = request.GET.get('error')
        
        # Handle LinkedIn errors
        if error:
            error_description = request.GET.get('error_description', 'LinkedIn authentication failed')
            return redirect(f"{redirect_url}?linkedin_error={error_description}")
        
        # Verify state for security
        if stored_state != returned_state:
            return redirect(f"{redirect_url}?linkedin_error=Invalid state parameter")
        
        if not code:
            return redirect(f"{redirect_url}?linkedin_error=Authorization code not received")
        
        try:
            # Exchange code for access token
            token_data = self.get_access_token(code)
            
            if 'error' in token_data:
                error_msg = token_data.get('error_description', 'Failed to obtain access token')
                return redirect(f"{redirect_url}?linkedin_error={error_msg}")
            
            access_token = token_data.get('access_token')
            if not access_token:
                return redirect(f"{redirect_url}?linkedin_error=No access token received")
            
            # Get LinkedIn profile data
            profile_data = self.get_linkedin_profile(access_token)
            email_data = self.get_linkedin_email(access_token)
            
            # Generate JWT token with LinkedIn data
            linkedin_token = self.generate_linkedin_token(profile_data, email_data)
            
            # Clear session data
            request.session.pop('linkedin_redirect_url', None)
            request.session.pop('linkedin_state', None)
            
            # Redirect with success token
            return redirect(f"{redirect_url}?linkedin_token={linkedin_token}")
            
        except Exception as e:
            return redirect(f"{redirect_url}?linkedin_error=Authentication failed: {str(e)}")
    
    def get_access_token(self, code):
        """Exchange authorization code for access token"""
        token_payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': LINKEDIN_REDIRECT_URI,
            'client_id': LINKEDIN_CLIENT_ID,
            'client_secret': LINKEDIN_CLIENT_SECRET,
        }
        
        response = requests.post(
            LINKEDIN_TOKEN_URL,
            data=token_payload,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=30
        )
        
        return response.json()
    
    def get_linkedin_profile(self, access_token):
        """Get LinkedIn profile information"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        response = requests.get(
            LINKEDIN_PROFILE_URL,
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch profile: {response.status_code}")
        
        return response.json()
    
    def get_linkedin_email(self, access_token):
        """Get LinkedIn email address"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        response = requests.get(
            LINKEDIN_EMAIL_URL,
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            email_data = response.json()
            elements = email_data.get('elements', [])
            if elements:
                return elements[0].get('handle~', {}).get('emailAddress')
        
        return None
    
    def generate_linkedin_token(self, profile_data, email):
        """Generate JWT token with LinkedIn profile data"""
        # Extract profile information
        linkedin_id = profile_data.get('id')
        first_name = profile_data.get('firstName', {}).get('localized', {}).get('en_US', '')
        last_name = profile_data.get('lastName', {}).get('localized', {}).get('en_US', '')
        
        # Create JWT payload
        payload = {
            'linkedin_id': linkedin_id,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'full_name': f"{first_name} {last_name}".strip(),
            'verified': True,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

@method_decorator(csrf_exempt, name='dispatch')
class LinkedInVerifyTokenView(View):
    """
    Verify LinkedIn JWT token and return profile data
    """
    def post(self, request):
        try:
            data = json.loads(request.body)
            linkedin_token = data.get('linkedin_token')
            
            if not linkedin_token:
                return JsonResponse({
                    'status': 'error',
                    'message': 'LinkedIn token is required'
                }, status=400)
            
            # Decode and verify token
            try:
                payload = jwt.decode(linkedin_token, JWT_SECRET_KEY, algorithms=['HS256'])
                
                return JsonResponse({
                    'status': 'success',
                    'data': {
                        'linkedin_id': payload.get('linkedin_id'),
                        'email': payload.get('email'),
                        'full_name': payload.get('full_name'),
                        'first_name': payload.get('first_name'),
                        'last_name': payload.get('last_name'),
                        'verified': payload.get('verified', False)
                    }
                })
                
            except jwt.ExpiredSignatureError:
                return JsonResponse({
                    'status': 'error',
                    'message': 'LinkedIn token has expired'
                }, status=400)
            
            except jwt.InvalidTokenError:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid LinkedIn token'
                }, status=400)
                
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