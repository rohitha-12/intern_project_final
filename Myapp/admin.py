from django.contrib import admin
from .models import CustomUser, EmailOTP, CompanyEmail, StripePayment

admin.site.register(CustomUser)
admin.site.register(EmailOTP)
admin.site.register(CompanyEmail)

# Register your models here.

@admin.register(StripePayment)
class StripePaymentAdmin(admin.ModelAdmin):
    list_display = ['customer_name', 'email', 'amount', 'currency', 'status', 'created_at']
    list_filter = ['status', 'currency', 'created_at']
    search_fields = ['customer_name', 'email', 'stripe_session_id']
    readonly_fields = ['stripe_session_id', 'stripe_payment_intent_id', 'created_at', 'updated_at']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Payment Information', {
            'fields': ('user', 'customer_name', 'company_name', 'email', 'product_name')
        }),
        ('Stripe Details', {
            'fields': ('stripe_session_id', 'stripe_payment_intent_id', 'status')
        }),
        ('Financial Details', {
            'fields': ('amount', 'currency')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )