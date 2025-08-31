"""
Authentication Forms

Provides forms for user authentication, registration, and management
with enhanced validation and security features.
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordChangeForm
from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
import re

from dashboard.models.auth import Role, User, PasswordHistory

User = get_user_model()


class EnhancedLoginForm(AuthenticationForm):
    """
    Enhanced login form with additional validation
    """
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username',
            'required': True,
            'autofocus': True
        })
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password',
            'required': True
        })
    )
    
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        })
    )
    
    def __init__(self, request=None, *args, **kwargs):
        super().__init__(request, *args, **kwargs)
        self.error_messages['invalid_login'] = (
            'Invalid username or password. Please try again.'
        )
    
    def clean(self):
        """
        Enhanced validation with security checks
        """
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        
        if username and password:
            # Check if user exists
            try:
                user = User.objects.get(username=username)
                
                # Check account status before authentication
                if user.is_account_locked():
                    raise ValidationError(
                        'Your account is temporarily locked due to multiple failed login attempts. '
                        'Please try again later or contact an administrator.',
                        code='account_locked'
                    )
                
                if not user.is_active:
                    raise ValidationError(
                        'Your account has been deactivated. Please contact an administrator.',
                        code='account_inactive'
                    )
                
                # Check IP restrictions if user has any
                if hasattr(self, 'request') and self.request:
                    client_ip = self._get_client_ip()
                    if not user.is_ip_allowed(client_ip):
                        raise ValidationError(
                            'Access denied from this IP address.',
                            code='ip_restricted'
                        )
                
            except User.DoesNotExist:
                pass  # Let the parent class handle invalid credentials
        
        return super().clean()
    
    def _get_client_ip(self):
        """Extract client IP from request"""
        if not self.request:
            return '0.0.0.0'
        
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = self.request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class UserCreationFormEnhanced(UserCreationForm):
    """
    Enhanced user creation form for admin use
    """
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email address'
        })
    )
    
    full_name = forms.CharField(
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Full name'
        })
    )
    
    department = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Department'
        })
    )
    
    phone = forms.CharField(
        max_length=20,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Phone number'
        })
    )
    
    role = forms.ModelChoiceField(
        queryset=Role.objects.filter(is_active=True),
        required=False,
        empty_label="Select role",
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    require_password_change = forms.BooleanField(
        required=False,
        initial=True,
        help_text="User must change password on first login",
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    allowed_ip_addresses = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'One IP address per line (leave empty for no restrictions)'
        }),
        help_text="Optional IP address restrictions, one per line"
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'full_name', 'department', 'phone', 'role')
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Username'
            })
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})
    
    def clean_username(self):
        """
        Validate username
        """
        username = self.cleaned_data['username']
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            raise ValidationError(
                'Username can only contain letters, numbers, underscores, dots, and hyphens.'
            )
        
        # Check minimum length
        if len(username) < 3:
            raise ValidationError('Username must be at least 3 characters long.')
        
        return username
    
    def clean_password1(self):
        """
        Enhanced password validation
        """
        password = self.cleaned_data.get('password1')
        
        if password:
            # Use Django's built-in password validation
            validate_password(password)
            
            # Additional custom validations
            if len(password) < 8:
                raise ValidationError('Password must be at least 8 characters long.')
            
            if not re.search(r'[A-Z]', password):
                raise ValidationError('Password must contain at least one uppercase letter.')
            
            if not re.search(r'[a-z]', password):
                raise ValidationError('Password must contain at least one lowercase letter.')
            
            if not re.search(r'\d', password):
                raise ValidationError('Password must contain at least one number.')
            
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', password):
                raise ValidationError('Password must contain at least one special character.')
        
        return password
    
    def clean_allowed_ip_addresses(self):
        """
        Validate IP addresses
        """
        ip_text = self.cleaned_data.get('allowed_ip_addresses', '').strip()
        if not ip_text:
            return []
        
        ip_addresses = []
        for line in ip_text.split('\n'):
            ip = line.strip()
            if ip:
                # Basic IP validation
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    raise ValidationError(f'Invalid IP address: {ip}')
                
                # Check octets
                octets = ip.split('.')
                for octet in octets:
                    if not (0 <= int(octet) <= 255):
                        raise ValidationError(f'Invalid IP address: {ip}')
                
                ip_addresses.append(ip)
        
        return ip_addresses
    
    def save(self, commit=True):
        """
        Save user with additional fields
        """
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.full_name = self.cleaned_data['full_name']
        user.department = self.cleaned_data['department']
        user.phone = self.cleaned_data['phone']
        user.role = self.cleaned_data['role']
        user.require_password_change = self.cleaned_data['require_password_change']
        user.allowed_ip_addresses = self.cleaned_data['allowed_ip_addresses']
        
        if commit:
            user.save()
            
            # Add password to history
            PasswordHistory.add_password(user, self.cleaned_data['password1'])
        
        return user


class UserEditForm(forms.ModelForm):
    """
    Form for editing existing users (admin only)
    """
    role = forms.ModelChoiceField(
        queryset=Role.objects.filter(is_active=True),
        required=False,
        empty_label="Select role",
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    allowed_ip_addresses = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'One IP address per line (leave empty for no restrictions)'
        }),
        help_text="Optional IP address restrictions, one per line"
    )
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'full_name', 'department', 'phone', 
            'role', 'is_active', 'max_concurrent_sessions', 
            'session_timeout_minutes'
        ]
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'full_name': forms.TextInput(attrs={'class': 'form-control'}),
            'department': forms.TextInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'max_concurrent_sessions': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 1,
                'max': 10
            }),
            'session_timeout_minutes': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 30,
                'max': 1440  # 24 hours
            })
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Populate IP addresses field
        if self.instance and self.instance.allowed_ip_addresses:
            self.fields['allowed_ip_addresses'].initial = '\n'.join(
                self.instance.allowed_ip_addresses
            )
    
    def clean_allowed_ip_addresses(self):
        """
        Validate IP addresses
        """
        ip_text = self.cleaned_data.get('allowed_ip_addresses', '').strip()
        if not ip_text:
            return []
        
        ip_addresses = []
        for line in ip_text.split('\n'):
            ip = line.strip()
            if ip:
                # Basic IP validation
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    raise ValidationError(f'Invalid IP address: {ip}')
                
                # Check octets
                octets = ip.split('.')
                for octet in octets:
                    if not (0 <= int(octet) <= 255):
                        raise ValidationError(f'Invalid IP address: {ip}')
                
                ip_addresses.append(ip)
        
        return ip_addresses
    
    def save(self, commit=True):
        """
        Save user with IP addresses
        """
        user = super().save(commit=False)
        user.allowed_ip_addresses = self.cleaned_data['allowed_ip_addresses']
        
        if commit:
            user.save()
        
        return user


class PasswordChangeFormEnhanced(PasswordChangeForm):
    """
    Enhanced password change form with history checking
    """
    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)
        self.fields['old_password'].widget.attrs.update({'class': 'form-control'})
        self.fields['new_password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['new_password2'].widget.attrs.update({'class': 'form-control'})
    
    def clean_new_password1(self):
        """
        Enhanced password validation with history check
        """
        password = self.cleaned_data.get('new_password1')
        
        if password:
            # Use Django's built-in password validation
            validate_password(password, self.user)
            
            # Check password history
            if PasswordHistory.is_password_used_recently(self.user, password):
                raise ValidationError(
                    'You cannot reuse any of your last 5 passwords. Please choose a different password.'
                )
            
            # Additional custom validations
            if len(password) < 8:
                raise ValidationError('Password must be at least 8 characters long.')
            
            if not re.search(r'[A-Z]', password):
                raise ValidationError('Password must contain at least one uppercase letter.')
            
            if not re.search(r'[a-z]', password):
                raise ValidationError('Password must contain at least one lowercase letter.')
            
            if not re.search(r'\d', password):
                raise ValidationError('Password must contain at least one number.')
            
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', password):
                raise ValidationError('Password must contain at least one special character.')
        
        return password
    
    def save(self, commit=True):
        """
        Save new password and update history
        """
        user = super().save(commit)
        
        if commit:
            # Update password change timestamp
            user.last_password_change = timezone.now()
            user.require_password_change = False
            user.save(update_fields=['last_password_change', 'require_password_change'])
            
            # Add to password history
            PasswordHistory.add_password(user, self.cleaned_data['new_password1'])
        
        return user


class UserProfileForm(forms.ModelForm):
    """
    Form for users to edit their own profile
    """
    class Meta:
        model = User
        fields = ['email', 'full_name', 'phone']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'full_name': forms.TextInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'})
        }


class RoleForm(forms.ModelForm):
    """
    Form for creating and editing roles
    """
    permissions = forms.ModelMultipleChoiceField(
        queryset=None,  # Will be set in __init__
        widget=forms.CheckboxSelectMultiple,
        required=False,
        help_text="Select Django permissions for this role"
    )
    
    class Meta:
        model = Role
        fields = [
            'name', 'level', 'description', 'is_active',
            'can_view_logs', 'can_export_logs', 'can_manage_devices',
            'can_configure_sources', 'can_view_analytics', 'can_manage_users',
            'can_view_audit', 'can_system_config'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'level': forms.Select(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3
            }),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_view_logs': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_export_logs': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_manage_devices': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_configure_sources': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_view_analytics': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_manage_users': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_view_audit': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_system_config': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Set up permissions queryset
        from django.contrib.auth.models import Permission
        self.fields['permissions'].queryset = Permission.objects.select_related(
            'content_type'
        ).order_by('content_type__app_label', 'codename')


class BulkUserActionForm(forms.Form):
    """
    Form for bulk user actions
    """
    ACTION_CHOICES = [
        ('activate', 'Activate Selected Users'),
        ('deactivate', 'Deactivate Selected Users'),
        ('unlock', 'Unlock Selected Users'),
        ('reset_password', 'Force Password Reset'),
    ]
    
    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(),
        widget=forms.CheckboxSelectMultiple
    )
    
    def __init__(self, *args, **kwargs):
        user_queryset = kwargs.pop('user_queryset', User.objects.all())
        super().__init__(*args, **kwargs)
        self.fields['users'].queryset = user_queryset