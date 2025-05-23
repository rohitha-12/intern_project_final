from django import forms

class PhoneForm(forms.Form):
    phone_number = forms.CharField(max_length=15)

class OTPForm(forms.Form):
    phone_number = forms.CharField(widget=forms.HiddenInput())
    otp = forms.CharField(max_length=6)