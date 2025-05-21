from django.contrib import admin
from .models import CustomUser, EmailOTP, CompanyEmail, StripePayment

admin.site.register(CustomUser)
admin.site.register(EmailOTP)
admin.site.register(CompanyEmail)
admin.site.register(StripePayment)

# Register your models here.
