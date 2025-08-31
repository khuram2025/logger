"""
Security Middleware for Enhanced Authentication System

Implements session security, timeout management, and comprehensive audit logging
for all user activities in the network analyzer platform.
"""

from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import logout
from django.utils import timezone
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages
from django.http import JsonResponse
from datetime import timedelta
import logging

from dashboard.models.auth import UserSession, AuditLog

logger = logging.getLogger(__name__)


class SessionSecurityMiddleware(MiddlewareMixin):
    """
    Enhanced session security middleware that manages:
    - Session timeout based on user preferences
    - Concurrent session limits
    - Session tracking and cleanup
    - Security-based session termination
    """
    
    def process_request(self, request):
        """
        Process incoming request for session security
        """
        # Skip security checks for authentication URLs
        skip_paths = [
            reverse('auth:login'),
            reverse('auth:logout'),
            '/admin/login/',
        ]
        
        # Allow static files
        if any(request.path.startswith(path) for path in ['/static/', '/media/']):
            return None
        
        if request.path in skip_paths:
            return None
        
        # Check if user is authenticated
        if not request.user.is_authenticated:
            return None
        
        try:
            # Get or create user session record
            session_key = request.session.session_key
            if not session_key:
                # Create session if it doesn't exist
                request.session.create()
                session_key = request.session.session_key
            
            # Get user session record
            try:
                user_session = UserSession.objects.get(
                    user=request.user,
                    session_key=session_key,
                    is_active=True
                )
                
                # Check if session is expired
                if user_session.is_expired():
                    logger.info(f"Session expired for user {request.user.username}")
                    user_session.end_session('timeout')
                    
                    AuditLog.log_action(
                        user=request.user,
                        action_type='auth',
                        action='Session expired',
                        result='success',
                        request=request
                    )
                    
                    logout(request)
                    messages.warning(request, 'Your session has expired. Please log in again.')
                    return redirect('auth:login')
                
                # Update last activity
                user_session.last_activity = timezone.now()
                user_session.save(update_fields=['last_activity'])
                
                # Update user activity
                request.user.update_activity()
                
                # Store session in request for other middleware/views
                request.user_session = user_session
            
            except UserSession.DoesNotExist:
                # Session record doesn't exist - this could be a security issue
                logger.warning(f"Missing session record for authenticated user {request.user.username}")
                
                # Check if user has too many active sessions
                active_sessions = request.user.get_active_sessions()
                if not request.user.can_create_session():
                    # End oldest session
                    oldest_session = active_sessions.order_by('created_at').first()
                    if oldest_session:
                        oldest_session.end_session('concurrent_limit')
                        logger.info(f"Ended oldest session for user {request.user.username} due to concurrent limit")
                
                # Create new session record
                client_ip = self._get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                
                user_session = UserSession.objects.create(
                    user=request.user,
                    session_key=session_key,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    expires_at=timezone.now() + timedelta(minutes=request.user.session_timeout_minutes)
                )
                
                request.user_session = user_session
                
                AuditLog.log_action(
                    user=request.user,
                    action_type='auth',
                    action='New session created',
                    result='success',
                    request=request,
                    details={'session_id': str(user_session.id)}
                )
        
        except Exception as e:
            logger.exception(f"Session security error for user {request.user.username}: {e}")
            
            # In case of error, log out user for security
            AuditLog.log_action(
                user=request.user,
                action_type='security',
                action='Session security error - user logged out',
                result='error',
                request=request,
                error_message=str(e)
            )
            
            logout(request)
            messages.error(request, 'A security error occurred. Please log in again.')
            return redirect('auth:login')
        
        return None
    
    def _get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class AuditLoggingMiddleware(MiddlewareMixin):
    """
    Comprehensive audit logging middleware that tracks all user actions
    """
    
    # Actions that should be logged
    LOG_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    
    # Paths that should always be logged
    ALWAYS_LOG_PATHS = [
        '/dashboard/devices/',
        '/dashboard/log-sources/',
        '/dashboard/users/',
        '/dashboard/system/',
        '/admin/',
    ]
    
    # Paths to skip logging
    SKIP_LOG_PATHS = [
        '/static/',
        '/media/',
        '/dashboard/api/heartbeat/',
        '/dashboard/api/stats/',
    ]
    
    # Sensitive fields to mask in logging
    SENSITIVE_FIELDS = ['password', 'password1', 'password2', 'old_password', 'new_password']
    
    def process_request(self, request):
        """
        Store request start time for performance tracking
        """
        request._audit_start_time = timezone.now()
        return None
    
    def process_response(self, request, response):
        """
        Log user actions and system access
        """
        # Skip if not authenticated (except login/logout)
        if not request.user.is_authenticated and not self._is_auth_action(request):
            return response
        
        # Skip certain paths
        if any(request.path.startswith(path) for path in self.SKIP_LOG_PATHS):
            return response
        
        # Determine if we should log this action
        should_log = (
            request.method in self.LOG_METHODS or
            any(path in request.path for path in self.ALWAYS_LOG_PATHS) or
            self._is_auth_action(request)
        )
        
        if should_log:
            try:
                self._log_action(request, response)
            except Exception as e:
                logger.exception(f"Audit logging error: {e}")
        
        return response
    
    def _log_action(self, request, response):
        """
        Log the user action
        """
        # Determine action type and description
        action_type, action = self._get_action_info(request)
        
        # Determine result based on response status
        if response.status_code < 300:
            result = 'success'
        elif response.status_code < 400:
            result = 'success'  # Redirects are usually success
        elif response.status_code == 403:
            result = 'denied'
        else:
            result = 'failure'
        
        # Get additional details
        details = self._get_action_details(request)
        
        # Calculate processing time
        if hasattr(request, '_audit_start_time'):
            processing_time = (timezone.now() - request._audit_start_time).total_seconds()
            details['processing_time_seconds'] = round(processing_time, 3)
        
        # Log the action
        AuditLog.log_action(
            user=request.user if request.user.is_authenticated else None,
            action_type=action_type,
            action=action,
            result=result,
            request=request,
            details=details
        )
    
    def _get_action_info(self, request):
        """
        Determine action type and description from request
        """
        path = request.path.lower()
        method = request.method
        
        # Authentication actions
        if 'login' in path:
            return 'auth', f'{method} Login attempt'
        elif 'logout' in path:
            return 'auth', f'{method} Logout'
        
        # User management
        if '/users/' in path or '/user/' in path:
            return 'user_mgmt', f'{method} User management: {path}'
        
        # Role management  
        if '/roles/' in path or '/role/' in path:
            return 'role_mgmt', f'{method} Role management: {path}'
        
        # Device management
        if '/devices/' in path or '/device/' in path:
            return 'device_mgmt', f'{method} Device management: {path}'
        
        # Log access
        if '/logs/' in path and method == 'GET':
            return 'log_access', f'Log data access: {path}'
        elif '/logs/' in path:
            return 'log_access', f'{method} Log management: {path}'
        
        # Log export
        if 'export' in path:
            return 'log_export', f'Data export: {path}'
        
        # Configuration changes
        if '/config' in path or '/settings' in path:
            return 'config_change', f'{method} Configuration change: {path}'
        
        # System access
        if '/admin/' in path:
            return 'system_access', f'{method} Admin interface: {path}'
        
        # Default to system access
        return 'system_access', f'{method} {path}'
    
    def _get_action_details(self, request):
        """
        Extract additional details from request
        """
        details = {}
        
        # Add query parameters
        if request.GET:
            details['query_params'] = dict(request.GET)
        
        # Add form data (excluding sensitive fields)
        if request.method in ['POST', 'PUT', 'PATCH'] and request.POST:
            form_data = {}
            for key, value in request.POST.items():
                if key.lower() in self.SENSITIVE_FIELDS:
                    form_data[key] = '[REDACTED]'
                else:
                    form_data[key] = value
            details['form_data'] = form_data
        
        # Add file uploads
        if request.FILES:
            details['files'] = list(request.FILES.keys())
        
        return details
    
    def _is_auth_action(self, request):
        """
        Check if this is an authentication-related action
        """
        auth_paths = ['login', 'logout', 'password']
        return any(path in request.path.lower() for path in auth_paths)


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers to all responses
    """
    
    def process_response(self, request, response):
        """
        Add security headers to response
        """
        # Prevent clickjacking
        response['X-Frame-Options'] = 'DENY'
        
        # Prevent content type sniffing
        response['X-Content-Type-Options'] = 'nosniff'
        
        # XSS protection
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer policy
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy (basic)
        if not response.get('Content-Security-Policy'):
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self';"
            )
            response['Content-Security-Policy'] = csp
        
        # HSTS (only for HTTPS)
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response


class IPWhitelistMiddleware(MiddlewareMixin):
    """
    Optional IP whitelist middleware for additional security
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        # This could be configured via settings
        self.whitelist_enabled = False  # Disable by default
        self.allowed_ips = ['127.0.0.1', '::1']  # Default to localhost only
    
    def process_request(self, request):
        """
        Check if client IP is in whitelist
        """
        if not self.whitelist_enabled:
            return None
        
        client_ip = self._get_client_ip(request)
        
        if client_ip not in self.allowed_ips:
            logger.warning(f"Access denied for IP {client_ip} - not in whitelist")
            
            AuditLog.log_action(
                user=None,
                action_type='security',
                action=f'Access denied - IP not whitelisted: {client_ip}',
                result='denied',
                request=request
            )
            
            return JsonResponse({'error': 'Access denied'}, status=403)
        
        return None
    
    def _get_client_ip(self, request):
        """Extract client IP from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip