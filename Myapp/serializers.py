from rest_framework import serializers
from .models import CustomUser, StripePayment

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'full_name', 'phone_number', 
            'website_name', 'linkedin_url', 'no_linkedin', 
            'email_verified', 'is_active', 'last_login'
        ]
        read_only_fields = ['id', 'email', 'email_verified', 'is_active', 'date_joined', 'last_login']
    
    def validate_phone_number(self, value):
        """
        Validate phone number format
        """
        if value and len(value.strip()) < 10:
            raise serializers.ValidationError("Phone number must be at least 10 digits long.")
        return value
    
    def validate_full_name(self, value):
        """
        Validate full name
        """
        if not value or len(value.strip()) < 2:
            raise serializers.ValidationError("Full name must be at least 2 characters long.")
        return value.strip()
    
    def validate_website_name(self, value):
        """
        Validate website/company name
        """
        if value and len(value.strip()) < 2:
            raise serializers.ValidationError("Company name must be at least 2 characters long.")
        return value.strip() if value else value

class StripePaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = StripePayment
        fields = ['id', 'user', 'email', 'amount', 'currency', 'status', 'created_at']
