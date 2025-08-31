from django.urls import path
from .views import auth

app_name = 'auth'

urlpatterns = [
    # Authentication URLs
    path('login/', auth.EnhancedLoginView.as_view(), name='login'),
    path('logout/', auth.EnhancedLogoutView.as_view(), name='logout'),
    path('password-change/', auth.password_change_required, name='password_change_required'),
    path('profile/', auth.user_profile, name='user_profile'),
    path('profile/', auth.user_profile, name='profile'),  # Alias for header template
    path('settings/', auth.profile_settings, name='profile_settings'),
    path('sessions/', auth.user_sessions, name='user_sessions'),
    path('sessions/', auth.user_sessions, name='my_sessions'),  # Alias for header template
    path('security/', auth.security_log, name='security_log'),
    path('notifications/', auth.all_notifications, name='all_notifications'),
    
    # System status
    path('system/status/', auth.system_status, name='system_status'),
    
    # User management (admin only)
    path('users/', auth.user_list, name='user_list'),
    path('users/create/', auth.user_create, name='user_create'),
    path('users/<uuid:user_id>/', auth.user_detail, name='user_detail'),
    path('users/<uuid:user_id>/edit/', auth.user_edit, name='user_edit'),
    path('users/<uuid:user_id>/lock-unlock/', auth.user_lock_unlock, name='user_lock_unlock'),
    
    # AJAX endpoints
    path('sessions/<uuid:session_id>/end/', auth.end_session, name='end_session'),
    
    # Audit logs
    path('audit-logs/', auth.audit_log_list, name='audit_logs'),
]