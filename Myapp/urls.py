from django.urls import path, include
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import LinkedInAuthView, LinkedInCallbackView, ExtractUserDataFromHeaderView

urlpatterns = [
    # Authentication paths
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('extract-user-data/', ExtractUserDataFromHeaderView.as_view(), name='extract-user-data'),
    
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
    path('forgot-password-send-otp/', views.ForgotPasswordSendOTP.as_view(), name='forgot_password_send_otp'),
    path('verify-otp/', views.VerifyOTP.as_view(), name='verify_otp'),
    path('reset-password/', views.ResetPassword.as_view(), name='reset_password'),
    path('list-company-emails/', views.ListCompanyEmailsView.as_view()),
    path('send-email-otp/', views.SendEmailOTPView.as_view()),
    path('verify-email-otp/', views.VerifyEmailOTPView.as_view()),
    path('set-primary-email/', views.SetPrimaryEmailView.as_view()),
    path('remove-email/', views.RemoveEmailView.as_view()),

    #payment history
    path('payment-history/', views.SuccessfulPaymentsView.as_view(), name='payment-history'),
    path('refund-history/', views.RefundPaymentsView.as_view(), name='refund-history'),

    #category statistics
    path('category-statistics/', views.read_excel_sheet_by_name, name='category-statistics'),

    #payment
    path('create-checkout-session/', views.CreateCheckoutSessionView.as_view(), name='create-checkout-session'),
    path('webhook/', views.StripeWebhookView.as_view(), name='stripe-webhook'),

    # Stripe Payment URLs
    path('create-checkout-session/', views.CreateCheckoutSessionView.as_view(), name='create-checkout-session'),
    path('stripe-webhook/', views.StripeWebhookView.as_view(), name='stripe-webhook'),
    path('payment-status/', views.PaymentStatusView.as_view(), name='payment-status'),
    path('user-payments/', views.UserPaymentsView.as_view(), name='user-payments'),
]