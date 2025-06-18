from django.urls import path
from . import views

urlpatterns = [
    path('logs/', views.clickhouse_logs_view, name='clickhouse_logs'),
    path('url-logs/', views.url_filtering_logs_view, name='url_filtering_logs'),
    path('top-summary/', views.top_summary_view, name='top_summary'),
    path('grouped-logs/', views.grouped_logs_view, name='grouped_logs'),
    path('system-config/', views.system_config_view, name='system_config'),
    path('service-action/', views.service_action_view, name='service_action'),
    path('logs-config/', views.logs_config_view, name='logs_config'),
    path('logs-config/save/', views.logs_config_save_view, name='logs_config_save'),
    path('logs-config/test/', views.logs_config_test_view, name='logs_config_test'),
    # Log Sources Management
    path('log-sources/', views.log_sources_view, name='log_sources'),
    path('logs-sources/toggle-save/', views.toggle_save_logs_view, name='toggle_save_logs'),
    path('logs-sources/action/', views.log_source_action_view, name='log_source_action'),
    path('logs-sources/test/', views.test_log_source_view, name='test_log_source'),
    path('logs-sources/scan/', views.scan_log_sources_view, name='scan_log_sources'),
    path('logs-sources/status/', views.log_sources_status_view, name='log_sources_status'),
    path('logs-sources/add/', views.add_log_source_view, name='add_log_source'),
    path('logs-sources/configure/<int:source_id>/', views.configure_log_source_view, name='configure_log_source'),
    path('logs-sources/configure/<int:source_id>/save/', views.save_log_source_config_view, name='save_log_source_config'),
    # Log Management
    path('log-management/', views.log_management_status_view, name='log_management'),
]
