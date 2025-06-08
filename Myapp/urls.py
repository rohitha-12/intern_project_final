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
    path('set-webinar-form-filled-by-email/', views.set_webinar_form_filled_by_email, name='set_webinar_form_filled_by_email'),
    
    # Email verification paths
    path('check_email_status/', views.check_email_status, name='check_email_status'),
    path('send_email_otp/', views.send_email_otp, name='send_email_otp'),
    path('verify_email_otp/', views.verify_email_otp, name='verify_email_otp'),
    
    # LinkedIn OAuth paths
    path('linkedin-auth/', LinkedInAuthView.as_view(), name='linkedin_auth'),
    path('linkedin-callback/', LinkedInCallbackView.as_view(), name='linkedin_callback'),

    #chat
    path('chat/<str:room_name>/', views.room, name='room'),
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
    path('check-username/', views.check_username_exists, name='check_username'),

    #payment history
    path('payment-history/', views.SuccessfulPaymentsView.as_view(), name='payment-history'),
    path('refund-history/', views.RefundPaymentsView.as_view(), name='refund-history'),

    #category statistics
    path('category-statistics/', views.read_excel_sheet_by_name, name='category-statistics'),
    path('category-list/', views.get_category_list, name='category-list'),


    # Stripe Payment URLs
    path('create-checkout-session/', views.CreateCheckoutSessionView.as_view(), name='create-checkout-session'),
    path('stripe-webhook/', views.StripeWebhookView.as_view(), name='stripe-webhook'),
    path('payment-status/', views.PaymentStatusView.as_view(), name='payment-status'),
    path('user-payments/', views.UserPaymentsView.as_view(), name='user-payments'),

    #vimeo URLs
    path('videos/public/<str:video_id>/', views.FetchPublicVideoView.as_view(), name='fetch-public-video'),
    path('videos/unlisted/<str:video_id>/', views.FetchUnlistedVideoView.as_view(), name='fetch-unlisted-video'),

    path('save-coi-form/', views.save_coi_form, name='save_coi_form'),
    path('process-payment/', views.ProcessPaymentView.as_view(), name='process-payment'),
    path('confirm-payment/', views.ConfirmPaymentView.as_view(), name='confirm-payment'),
    path('process-tokenized-payment/', views.ProcessTokenizedPaymentView.as_view(), name='process-tokenized-payment'),
]