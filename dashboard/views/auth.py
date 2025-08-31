"""
Authentication Views

Handles login, logout, user management, and authentication-related views
with enhanced security features.
"""

from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.urls import reverse_lazy, reverse
from django.views.generic import CreateView, UpdateView, DeleteView, ListView, DetailView
from django.http import JsonResponse, HttpResponseForbidden
from django.db import transaction
from django.core.paginator import Paginator
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from datetime import timedelta
import logging

from dashboard.models.auth import User, Role, UserSession, AuditLog, LoginAttempt
from dashboard.auth.decorators import (
    require_permission, admin_required, can_manage_users,
    ajax_permission_required, MethodPermissionMixin
)
from dashboard.auth.backends import PermissionCache

logger = logging.getLogger(__name__)

User = get_user_model()


class EnhancedLoginView(LoginView):
    """
    Enhanced login view with security features
    """
    template_name = 'dashboard/auth/login.html'
    redirect_authenticated_user = True
    
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        """
        Handle successful authentication
        """
        user = form.get_user()
        
        # Check if user requires password change
        if user.require_password_change:
            messages.warning(
                self.request,
                'You must change your password before continuing.'
            )
            # Store user ID in session for password change
            self.request.session['password_change_required'] = str(user.id)
            return redirect('auth:password_change_required')
        
        # Create session record
        self.create_user_session(user)
        
        # Perform login
        login(self.request, user)
        
        # Log successful login (done by authentication backend)
        messages.success(self.request, f'Welcome back, {user.get_display_name()}!')
        
        return super().form_valid(form)
    
    def form_invalid(self, form):
        """
        Handle failed authentication
        """
        # Login attempt logging is handled by the authentication backend
        messages.error(self.request, 'Invalid username or password.')
        return super().form_invalid(form)
    
    def create_user_session(self, user):
        """
        Create user session record for security tracking
        """
        try:
            # End any existing sessions if user exceeds limit
            active_sessions = user.get_active_sessions()
            if not user.can_create_session():
                # End oldest session
                oldest_session = active_sessions.order_by('created_at').first()
                if oldest_session:
                    oldest_session.end_session('concurrent_limit')
                    logger.info(f"Ended oldest session for user {user.username} due to concurrent limit")
            
            # Create new session
            client_ip = self.get_client_ip()
            user_agent = self.request.META.get('HTTP_USER_AGENT', '')
            
            # Ensure session exists
            if not self.request.session.session_key:
                self.request.session.create()
            
            session = UserSession.objects.create(
                user=user,
                session_key=self.request.session.session_key,
                ip_address=client_ip,
                user_agent=user_agent,
                expires_at=timezone.now() + timedelta(minutes=user.session_timeout_minutes)
            )
            
            logger.info(f"Created new session for user {user.username} from IP {client_ip}")
            
        except Exception as e:
            logger.exception(f"Error creating session for user {user.username}: {e}")
    
    def get_client_ip(self):
        """Extract client IP from request"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = self.request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip
    
    def get_success_url(self):
        """
        Determine where to redirect after successful login
        """
        # Check for next parameter
        next_url = self.request.GET.get('next')
        if next_url:
            return next_url
        
        # Default to dashboard
        return reverse('index')


class EnhancedLogoutView(LogoutView):
    """
    Enhanced logout view with session cleanup
    """
    next_page = reverse_lazy('auth:login')
    
    def dispatch(self, request, *args, **kwargs):
        """
        Clean up user session before logout
        """
        if request.user.is_authenticated:
            try:
                # Find and end user session
                session_key = request.session.session_key
                if session_key:
                    user_session = UserSession.objects.filter(
                        user=request.user,
                        session_key=session_key,
                        is_active=True
                    ).first()
                    
                    if user_session:
                        user_session.end_session('logout')
                
                # Log the logout
                AuditLog.log_action(
                    user=request.user,
                    action_type='auth',
                    action='User logout',
                    result='success',
                    request=request
                )
                
                messages.success(request, 'You have been logged out successfully.')
                
            except Exception as e:
                logger.exception(f"Error during logout for user {request.user.username}: {e}")
        
        return super().dispatch(request, *args, **kwargs)


@login_required
def password_change_required(request):
    """
    Force password change for users who require it
    """
    # Check if user ID is in session (from login view)
    user_id = request.session.get('password_change_required')
    if not user_id or str(request.user.id) != user_id:
        return redirect('index')
    
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')
        
        # Validate passwords
        if not authenticate(username=request.user.username, password=old_password):
            messages.error(request, 'Current password is incorrect.')
        elif new_password1 != new_password2:
            messages.error(request, 'New passwords do not match.')
        elif len(new_password1) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
        else:
            # Change password
            request.user.set_password(new_password1)
            request.user.require_password_change = False
            request.user.last_password_change = timezone.now()
            request.user.save()
            
            # Remove session flag
            del request.session['password_change_required']
            
            # Log password change
            AuditLog.log_action(
                user=request.user,
                action_type='user_mgmt',
                action='Required password change completed',
                result='success',
                request=request
            )
            
            messages.success(request, 'Password changed successfully. You may now access the system.')
            return redirect('index')
    
    return render(request, 'dashboard/auth/password_change_required.html')


@can_manage_users
def user_list(request):
    """
    List all users (admin only)
    """
    users = User.objects.select_related('role').order_by('username')
    
    # Apply search filter
    search = request.GET.get('search')
    if search:
        users = users.filter(
            username__icontains=search
        ) | users.filter(
            full_name__icontains=search
        ) | users.filter(
            email__icontains=search
        )
    
    # Apply role filter
    role_filter = request.GET.get('role')
    if role_filter:
        users = users.filter(role__name=role_filter)
    
    # Apply status filter
    status_filter = request.GET.get('status')
    if status_filter == 'active':
        users = users.filter(is_active=True, account_locked=False)
    elif status_filter == 'inactive':
        users = users.filter(is_active=False)
    elif status_filter == 'locked':
        users = users.filter(account_locked=True)
    
    # Pagination
    paginator = Paginator(users, 25)  # 25 users per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get all roles for filter dropdown
    roles = Role.objects.filter(is_active=True).order_by('level', 'name')
    
    context = {
        'page_obj': page_obj,
        'roles': roles,
        'search': search,
        'role_filter': role_filter,
        'status_filter': status_filter,
    }
    
    return render(request, 'dashboard/auth/user_list.html', context)


@can_manage_users
def user_detail(request, user_id):
    """
    View user details (admin only)
    """
    user = get_object_or_404(User, id=user_id)
    
    # Get recent sessions
    recent_sessions = user.sessions.order_by('-created_at')[:10]
    
    # Get recent login attempts
    recent_attempts = LoginAttempt.objects.filter(
        username=user.username
    ).order_by('-timestamp')[:10]
    
    # Get recent audit logs
    recent_audit = user.audit_logs.order_by('-timestamp')[:20]
    
    context = {
        'user_obj': user,  # Avoid conflict with request.user
        'recent_sessions': recent_sessions,
        'recent_attempts': recent_attempts,
        'recent_audit': recent_audit,
    }
    
    return render(request, 'dashboard/auth/user_detail.html', context)


@can_manage_users
def user_create(request):
    """
    Create new user (admin only)
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        full_name = request.POST.get('full_name')
        role_id = request.POST.get('role')
        password = request.POST.get('password')
        require_password_change = request.POST.get('require_password_change') == 'on'
        
        # Validation
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
        elif not password or len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
        else:
            try:
                role = Role.objects.get(id=role_id) if role_id else None
                
                with transaction.atomic():
                    user = User.objects.create_user(
                        username=username,
                        email=email,
                        password=password,
                        full_name=full_name,
                        role=role,
                        require_password_change=require_password_change,
                        created_by=request.user
                    )
                    
                    # Log user creation
                    AuditLog.log_action(
                        user=request.user,
                        action_type='user_mgmt',
                        action=f'Created new user: {username}',
                        result='success',
                        request=request,
                        resource_type='user',
                        resource_id=str(user.id),
                        resource_name=username,
                        details={
                            'new_user_id': str(user.id),
                            'role': role.name if role else 'None',
                            'require_password_change': require_password_change
                        }
                    )
                
                messages.success(request, f'User {username} created successfully.')
                return redirect('auth:user_list')
                
            except Exception as e:
                logger.exception(f"Error creating user {username}: {e}")
                messages.error(request, f'Error creating user: {str(e)}')
    
    # Get available roles
    roles = Role.objects.filter(is_active=True).order_by('level', 'name')
    
    context = {
        'roles': roles,
    }
    
    return render(request, 'dashboard/auth/user_create.html', context)


@can_manage_users
def user_edit(request, user_id):
    """
    Edit existing user (admin only)
    """
    user_obj = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        email = request.POST.get('email')
        full_name = request.POST.get('full_name')
        role_id = request.POST.get('role')
        is_active = request.POST.get('is_active') == 'on'
        
        # Store old values for audit log
        old_values = {
            'email': user_obj.email,
            'full_name': user_obj.full_name,
            'role': user_obj.role.name if user_obj.role else None,
            'is_active': user_obj.is_active
        }
        
        try:
            role = Role.objects.get(id=role_id) if role_id else None
            
            with transaction.atomic():
                user_obj.email = email
                user_obj.full_name = full_name
                user_obj.role = role
                user_obj.is_active = is_active
                user_obj.save()
                
                # Clear cached permissions
                PermissionCache.clear_cached_permissions(user_obj)
                
                # New values for audit log
                new_values = {
                    'email': user_obj.email,
                    'full_name': user_obj.full_name,
                    'role': user_obj.role.name if user_obj.role else None,
                    'is_active': user_obj.is_active
                }
                
                # Log user modification
                AuditLog.log_action(
                    user=request.user,
                    action_type='user_mgmt',
                    action=f'Modified user: {user_obj.username}',
                    result='success',
                    request=request,
                    resource_type='user',
                    resource_id=str(user_obj.id),
                    resource_name=user_obj.username,
                    old_values=old_values,
                    new_values=new_values
                )
            
            messages.success(request, f'User {user_obj.username} updated successfully.')
            return redirect('auth:user_detail', user_id=user_obj.id)
            
        except Exception as e:
            logger.exception(f"Error updating user {user_obj.username}: {e}")
            messages.error(request, f'Error updating user: {str(e)}')
    
    # Get available roles
    roles = Role.objects.filter(is_active=True).order_by('level', 'name')
    
    context = {
        'user_obj': user_obj,
        'roles': roles,
    }
    
    return render(request, 'dashboard/auth/user_edit.html', context)


@can_manage_users
@ajax_permission_required('manage_users')
def user_lock_unlock(request, user_id):
    """
    Lock or unlock user account (AJAX endpoint)
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    user_obj = get_object_or_404(User, id=user_id)
    action = request.POST.get('action')
    
    if action == 'lock':
        duration_hours = int(request.POST.get('duration_hours', 24))
        user_obj.lock_account(duration_hours=duration_hours)
        
        # End all active sessions
        active_sessions = user_obj.get_active_sessions()
        for session in active_sessions:
            session.end_session('admin_end')
        
        # Log the action
        AuditLog.log_action(
            user=request.user,
            action_type='user_mgmt',
            action=f'Locked user account: {user_obj.username}',
            result='success',
            request=request,
            resource_type='user',
            resource_id=str(user_obj.id),
            resource_name=user_obj.username,
            details={'duration_hours': duration_hours}
        )
        
        return JsonResponse({
            'success': True,
            'message': f'User {user_obj.username} has been locked for {duration_hours} hours.',
            'status': 'locked'
        })
    
    elif action == 'unlock':
        user_obj.unlock_account()
        
        # Log the action
        AuditLog.log_action(
            user=request.user,
            action_type='user_mgmt',
            action=f'Unlocked user account: {user_obj.username}',
            result='success',
            request=request,
            resource_type='user',
            resource_id=str(user_obj.id),
            resource_name=user_obj.username
        )
        
        return JsonResponse({
            'success': True,
            'message': f'User {user_obj.username} has been unlocked.',
            'status': 'unlocked'
        })
    
    else:
        return JsonResponse({'error': 'Invalid action'}, status=400)


@require_permission('view_audit')
def audit_log_list(request):
    """
    View audit logs (admin only)
    """
    logs = AuditLog.objects.select_related('user').order_by('-timestamp')
    
    # Apply filters
    user_filter = request.GET.get('user')
    if user_filter:
        logs = logs.filter(user_id=user_filter)
    
    action_type_filter = request.GET.get('action_type')
    if action_type_filter:
        logs = logs.filter(action_type=action_type_filter)
    
    result_filter = request.GET.get('result')
    if result_filter:
        logs = logs.filter(result=result_filter)
    
    # Date range filter
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)
    
    # Pagination
    paginator = Paginator(logs, 50)  # 50 logs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get filter options
    action_types = AuditLog.objects.values_list('action_type', flat=True).distinct()
    results = AuditLog.objects.values_list('result', flat=True).distinct()
    users = User.objects.filter(audit_logs__isnull=False).distinct().order_by('username')
    
    context = {
        'page_obj': page_obj,
        'action_types': action_types,
        'results': results,
        'users': users,
        'filters': {
            'user': user_filter,
            'action_type': action_type_filter,
            'result': result_filter,
            'date_from': date_from,
            'date_to': date_to,
        }
    }
    
    return render(request, 'dashboard/auth/audit_log_list.html', context)


@login_required
def user_profile(request):
    """
    View/edit user's own profile
    """
    if request.method == 'POST':
        email = request.POST.get('email')
        full_name = request.POST.get('full_name')
        phone = request.POST.get('phone')
        
        # Store old values
        old_values = {
            'email': request.user.email,
            'full_name': request.user.full_name,
            'phone': request.user.phone,
        }
        
        # Update profile
        request.user.email = email
        request.user.full_name = full_name
        request.user.phone = phone
        request.user.save()
        
        # Log profile update
        AuditLog.log_action(
            user=request.user,
            action_type='user_mgmt',
            action='Updated own profile',
            result='success',
            request=request,
            old_values=old_values,
            new_values={
                'email': request.user.email,
                'full_name': request.user.full_name,
                'phone': request.user.phone,
            }
        )
        
        messages.success(request, 'Profile updated successfully.')
        return redirect('auth:user_profile')
    
    return render(request, 'dashboard/auth/user_profile.html')


@login_required
def user_sessions(request):
    """
    View user's active sessions
    """
    sessions = request.user.sessions.filter(is_active=True).order_by('-created_at')
    
    context = {
        'sessions': sessions,
        'current_session_key': request.session.session_key,
    }
    
    return render(request, 'dashboard/auth/user_sessions.html', context)


@login_required
@ajax_permission_required('view_logs')  # Users can manage their own sessions
def end_session(request, session_id):
    """
    End a user session (AJAX endpoint)
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    # Get session - users can only end their own sessions unless they're admin
    if PermissionCache.has_permission(request.user, 'manage_users'):
        user_session = get_object_or_404(UserSession, id=session_id)
    else:
        user_session = get_object_or_404(UserSession, id=session_id, user=request.user)
    
    # Don't allow ending current session this way
    if user_session.session_key == request.session.session_key:
        return JsonResponse({'error': 'Cannot end current session'}, status=400)
    
    # End the session
    user_session.end_session('admin_end')
    
    # Log the action
    AuditLog.log_action(
        user=request.user,
        action_type='auth',
        action=f'Ended session: {user_session.id}',
        result='success',
        request=request,
        details={
            'ended_session_user': user_session.user.username,
            'ended_session_ip': user_session.ip_address
        }
    )
    
    return JsonResponse({
        'success': True,
        'message': 'Session ended successfully.'
    })


@login_required
def profile_settings(request):
    """
    User account settings - password change, preferences, etc.
    """
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'change_password':
            current_password = request.POST.get('current_password')
            new_password1 = request.POST.get('new_password1')
            new_password2 = request.POST.get('new_password2')
            
            # Validate current password
            if not authenticate(username=request.user.username, password=current_password):
                messages.error(request, 'Current password is incorrect.')
            elif new_password1 != new_password2:
                messages.error(request, 'New passwords do not match.')
            elif len(new_password1) < 8:
                messages.error(request, 'Password must be at least 8 characters long.')
            else:
                # Change password
                request.user.set_password(new_password1)
                request.user.last_password_change = timezone.now()
                request.user.save()
                
                # Log password change
                AuditLog.log_action(
                    user=request.user,
                    action_type='user_mgmt',
                    action='Changed password',
                    result='success',
                    request=request
                )
                
                messages.success(request, 'Password changed successfully.')
                return redirect('auth:profile_settings')
        
        elif action == 'update_preferences':
            # Handle user preferences updates
            session_timeout = request.POST.get('session_timeout_minutes', 30)
            try:
                session_timeout = max(15, min(480, int(session_timeout)))  # 15 min to 8 hours
                request.user.session_timeout_minutes = session_timeout
                request.user.save()
                
                messages.success(request, 'Preferences updated successfully.')
            except ValueError:
                messages.error(request, 'Invalid session timeout value.')
    
    return render(request, 'dashboard/auth/profile_settings.html')


@login_required
def security_log(request):
    """
    User's personal security activity log
    """
    # Get user's login attempts
    login_attempts = LoginAttempt.objects.filter(
        username=request.user.username
    ).order_by('-timestamp')[:50]
    
    # Get user's sessions
    sessions = request.user.sessions.order_by('-created_at')[:20]
    
    # Get user's audit logs (actions they performed)
    audit_logs = request.user.audit_logs.order_by('-timestamp')[:50]
    
    context = {
        'login_attempts': login_attempts,
        'sessions': sessions,
        'audit_logs': audit_logs,
    }
    
    return render(request, 'dashboard/auth/security_log.html', context)


@login_required
def all_notifications(request):
    """
    All user notifications with pagination
    """
    # For now, return a placeholder as the notification system isn't implemented
    # In a real implementation, this would fetch user notifications
    notifications = []  # User.notifications.all() when implemented
    
    context = {
        'notifications': notifications,
        'total_count': len(notifications),
        'unread_count': 0,
    }
    
    return render(request, 'dashboard/auth/notifications.html', context)


@require_permission('view_system')
def system_status(request):
    """
    System status overview (admin only)
    """
    try:
        from django.db import connection
        from datetime import datetime
        import psutil
        import os
        
        # Database status
        db_status = 'Connected'
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        except Exception as e:
            db_status = f'Error: {str(e)}'
        
        # System metrics
        system_info = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': psutil.virtual_memory(),
            'disk': psutil.disk_usage('/'),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()),
            'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else 'N/A',
        }
        
        # Service statuses (simplified)
        services = [
            {'name': 'Django Application', 'status': 'Running', 'uptime': 'N/A'},
            {'name': 'ClickHouse Database', 'status': 'Unknown', 'uptime': 'N/A'},
            {'name': 'Syslog Receiver', 'status': 'Unknown', 'uptime': 'N/A'},
        ]
        
        # Active users
        active_users_count = User.objects.filter(
            sessions__is_active=True,
            sessions__expires_at__gt=timezone.now()
        ).distinct().count()
        
        context = {
            'db_status': db_status,
            'system_info': system_info,
            'services': services,
            'active_users_count': active_users_count,
            'total_users_count': User.objects.count(),
        }
        
    except ImportError:
        # psutil not available, provide basic info
        context = {
            'db_status': 'Connected',
            'system_info': {'error': 'System monitoring not available (psutil required)'},
            'services': [],
            'active_users_count': User.objects.filter(
                sessions__is_active=True,
                sessions__expires_at__gt=timezone.now()
            ).distinct().count(),
            'total_users_count': User.objects.count(),
        }
    except Exception as e:
        logger.exception(f"Error getting system status: {e}")
        context = {
            'error': 'Unable to retrieve system status',
            'total_users_count': User.objects.count(),
        }
    
    return render(request, 'dashboard/auth/system_status.html', context)