from django.urls import path, include
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import LinkedInAuthView, LinkedInCallbackView

urlpatterns = [
    # Authentication paths
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Email verification paths
    path('check_email_status/', views.check_email_status, name='check_email_status'),
    path('send_email_otp/', views.send_email_otp, name='send_email_otp'),
    path('verify_email_otp/', views.verify_email_otp, name='verify_email_otp'),
    
    # LinkedIn OAuth paths
    path('linkedin-auth/', LinkedInAuthView.as_view(), name='linkedin_auth'),
    path('linkedin-callback/', LinkedInCallbackView.as_view(), name='linkedin_callback'),

    #chat
    path('room/', views.room, name='room'),
    path('ai-chatbox/', views.ai_chatbox, name='ai_chatbox'),

    #settings
    path('sections/', views.SettingsSectionsView.as_view(), name='settings-sections'),
    path('profile/', views.UserProfileView.as_view(), name='user-profile'),
    path('change-username/', views.ChangeUsernameView.as_view(), name='change-username'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('forgot-password/', views.ForgotPasswordSendOTP.as_view(), name='forgot_password_send_otp'),
    path('verify-otp/', views.VerifyOTP.as_view(), name='verify_otp'),
    path('reset-password/', views.ResetPassword.as_view(), name='reset_password'),
    path('add-email/', views.SendEmailOTPView.as_view(), name='add-email'),
    path('verify-email/', views.VerifyEmailOTPView.as_view(), name='verify_email'),
    path('list-emails/', views.ListCompanyEmailsView.as_view(), name='list-emails'),
    path('set-primary/', views.SetPrimaryEmailView.as_view(), name='set-primary'),
    path('remove-email/', views.RemoveEmailView.as_view(), name='remove-primary'),

    #payment history
    path('payment-history/', views.SuccessfulPaymentsView.as_view(), name='payment-history'),
    path('refund-history/', views.RefundPaymentsView.as_view(), name='refund-history'),


]