import re
from django import forms
from django.core.exceptions import ValidationError
from .models import RsyslogHost, LogRetentionPolicy

class RsyslogHostForm(forms.ModelForm):
    class Meta:
        model = RsyslogHost
        fields = ['address']

class LogRetentionPolicyForm(forms.ModelForm):
    class Meta:
        model = LogRetentionPolicy
        fields = ['enabled', 'interval', 'max_size', 'keep_rotations']

    def clean_max_size(self):
        max_size = self.cleaned_data.get('max_size')
        if max_size: # Only validate if not blank
            if not re.fullmatch(r'^\d+[MG]$', max_size):
                raise ValidationError(
                    "Invalid format. Max size must be a number followed by 'M' or 'G' (e.g., 100M, 5G)."
                )
        return max_size
