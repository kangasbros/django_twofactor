from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate
from django.contrib.auth.models import User

ERROR_MESSAGE = _("Please enter the correct username, password and "
    "authentication code (if applicable). Note that all fields are "
    "case-sensitive.")


class TwoFactorAuthenticationForm(AuthenticationForm):
    token = forms.CharField(label=_("Authentication Code"),
        help_text="If you have enabled two-factor authentication on your user account enter the six-digit number from your Google Authenticator mobile app here. Otherwise leave empty.",
        widget=forms.TextInput(attrs={'maxlength':'6', 'autocomplete': 'off'}),
        required=False
    )

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        token = self.cleaned_data.get('token')

        # Allow login with email
        try:
            u = User.objects.get(username=username)
        except User.DoesNotExist:
            try:
                u = User.objects.get(email=username)
                username = u.username
            except User.DoesNotExist:
                pass

        if username and password:
            self.user_cache = authenticate(username=username, password=password, token=token)
            if self.user_cache is None:
                raise forms.ValidationError(ERROR_MESSAGE)
            elif not self.user_cache.is_active:
                raise forms.ValidationError(_("This account is inactive."))
        self.check_for_test_cookie()
        return self.cleaned_data


class TwoFactorAdminAuthenticationForm(AuthenticationForm):
    token = forms.IntegerField(label=_("Authentication Code"),
        help_text="If you have enabled two-factor authentication, enter the "
            "six-digit number from your authentication device here.",
        widget=forms.TextInput(attrs={'maxlength':'6'}),
        min_value=1, max_value=999999,
        required=False
    )
    this_is_the_login_form = forms.BooleanField(widget=forms.HiddenInput,
        initial=1,  error_messages={'required': _("Please log in again, "
            "because your session has expired.")})

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        token = self.cleaned_data.get('token')

        if username and password:
            self.user_cache = authenticate(username=username, password=password, token=token)
            if self.user_cache is None:
                raise forms.ValidationError(ERROR_MESSAGE)
            elif not self.user_cache.is_active:
                raise forms.ValidationError(_("This account is inactive."))
        self.check_for_test_cookie()
        return self.cleaned_data
