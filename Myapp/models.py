import random
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import User
import time
class CustomUserManager(BaseUserManager):
    COLOR_OPTIONS = [
        'Red', 'Blue', 'Green', 'Yellow', 'Purple', 'Orange', 'Pink', 'Black', 
        'White', 'Gray', 'Brown', 'Cyan', 'Magenta', 'Lime', 'Indigo', 'Violet'
    ]
    
    OBJECT_OPTIONS = [
        'Cat', 'Dog', 'Bird', 'Fish', 'Tree', 'Star', 'Moon', 'Sun', 'Car', 'Book',
        'Phone', 'House', 'Flower', 'Rock', 'Cloud', 'Fire', 'Water', 'Mountain',
        'Ocean', 'River', 'Forest', 'Garden', 'Bridge', 'Tower', 'Castle', 'Ship'
    ]
    
    def generate_unique_username(self, max_attempts=50):
        """
        Generate a unique username in the format: ColorObjectNumber
        e.g., RedCat123, BlueStar456
        """
        for attempt in range(max_attempts):
            # Randomly select color and object
            color = random.choice(self.COLOR_OPTIONS)
            obj = random.choice(self.OBJECT_OPTIONS)
            
            # Generate random number between 1 and 9999
            number = random.randint(1, 9999)
            
            # Create username
            username = f"{color}{obj}{number}"
            
            # Check if username already exists
            if not self.model.objects.filter(username=username).exists():
                return username
        
        # Fallback: if we can't generate a unique username after max_attempts,
        # add timestamp to ensure uniqueness
        color = random.choice(self.COLOR_OPTIONS)
        obj = random.choice(self.OBJECT_OPTIONS)
        timestamp = str(int(time.time()))[-4:]  # Last 4 digits of timestamp
        return f"{color}{obj}{timestamp}"
    
    def create_user(self, email, username=None, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        
        # Generate username in the same format as frontend
        username = self.generate_unique_username()
        
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, username, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    full_name = models.CharField(max_length=100)
    username = models.CharField(max_length=50)
    email = models.EmailField(unique=True)``
    phone_number = models.CharField(max_length=15)
    linkedin_url = models.URLField(blank=True, null=True)
    linkedin_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    no_linkedin = models.BooleanField(default=False)
    paid = models.BooleanField(default=False)
    iswebinarformfilled = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    website_name = models.CharField(max_length=200, blank=True, null=True)
    email_otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email
    
    
    def is_otp_expired(self):
        if not self.otp_created_at:
            return True
        return timezone.now() > self.otp_created_at + timezone.timedelta(minutes=10)
    

class EmailOTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=10)


class PhoneOTP(models.Model):
    phone_number = models.CharField(max_length=15, unique=True)
    otp = models.CharField(max_length=6)
    is_verified = models.BooleanField(default=False)
    otp_created_at = models.DateTimeField(auto_now_add=True) 

    def is_otp_expired(self):
        return timezone.now() > self.otp_created_at + timedelta(minutes=5)

class EmailVerification(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    is_verified = models.BooleanField(default=False)
    is_registered = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        # OTP expires after 10 minutes
        return timezone.now() > self.created_at + timezone.timedelta(minutes=10)

class CompanyEmail(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='company_emails')
    email = models.EmailField(unique=True)
    verified = models.BooleanField(default=False)
    is_primary = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.email} ({'Primary' if self.is_primary else 'Secondary'}, {'Verified' if self.verified else 'Unverified'})"

    def save(self, *args, **kwargs):
        # Ensure only one primary email per user
        if self.is_primary:
            CompanyEmail.objects.filter(user=self.user, is_primary=True).update(is_primary=False)
        super().save(*args, **kwargs)

class StripePayment(models.Model):
    stripe_session_id = models.CharField(max_length=255, unique=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='stripe_payments')
    email = models.EmailField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10)
    status = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.email} - {self.amount} {self.currency} - {self.status}"
    
from django.contrib.auth import get_user_model

User = get_user_model()

class StripePayment(models.Model):
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('succeeded', 'Succeeded'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='stripe_payments')
    stripe_session_id = models.CharField(max_length=255, unique=True)
    stripe_payment_intent_id = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='usd')
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    customer_name = models.CharField(max_length=255, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True)
    product_name = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'stripe_payments'
        ordering = ['-created_at']
        verbose_name = 'Stripe Payment'
        verbose_name_plural = 'Stripe Payments'
    
    def __str__(self):
        return f"{self.customer_name} - ${self.amount} ({self.status})"
    
    @property
    def amount_in_cents(self):
        """Convert amount to cents for Stripe API"""
        return int(self.amount * 100)
    
    @property
    def is_successful(self):
        """Check if payment was successful"""
        return self.status in ['completed', 'succeeded']


class VimeoVideo(models.Model):
    video_id = models.CharField(max_length=255, unique=True)
    video_url = models.URLField()
    is_public = models.BooleanField()
    fetched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.video_id
    
class COIFormData(models.Model):
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)
    website_name = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'coi_form_data'

class ChatRoom(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class Message(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_pinned = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username}: {self.content[:30]}"

class UserMembership(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    is_member = models.BooleanField(default=False)
    is_webinar_form_submitted = models.BooleanField(default=False) 

    def __str__(self):
        return f"{self.user.username} - {'Member' if self.is_member else 'Not Member'}"

class AdminProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    display_name = models.CharField(max_length=100, default="Admin")

    def __str__(self):
        return f"{self.display_name} ({self.user.email})"


class Meeting(models.Model):
    DURATION_CHOICES = [
        (15, '15 minutes'),
        (30, '30 minutes'),
        (45, '45 minutes'),
        (60, '60 minutes'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='meetings')
    date = models.DateField()
    time = models.TimeField()
    duration = models.IntegerField(choices=DURATION_CHOICES, default=30)
    timezone = models.CharField(max_length=50, default='UTC')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'meetings'
        ordering = ['date', 'time']
        unique_together = ('date', 'time', 'user')  # Prevent double booking
    
    def __str__(self):
        return f"{self.user.email} - {self.date} {self.time} ({self.duration}min)"
    
    def clean(self):
        # Validate that the meeting is not in the past
        if self.date and self.time:
            meeting_datetime = timezone.datetime.combine(self.date, self.time)
            if meeting_datetime < timezone.now():
                raise ValidationError("Cannot schedule meetings in the past.")
    
    @property
    def end_time(self):
        """Calculate end time based on start time and duration"""
        start_datetime = timezone.datetime.combine(self.date, self.time)
        end_datetime = start_datetime + timezone.timedelta(minutes=self.duration)
        return end_datetime.time()