"""
URL configuration for fwanalyzer project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from dashboard import views as dashboard_views
from dashboard.views_grouped_logs import grouped_logs_view

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Authentication URLs - direct access at /auth/
    path('auth/', include('dashboard.urls_auth')),
    
    # Legacy redirects for backward compatibility
    path('login/', lambda request: redirect('/auth/login/')),
    path('logout/', lambda request: redirect('/auth/logout/')),
    
    path('dashboard/', include('dashboard.urls')),
    
    # Root URLs - direct access without namespace for main views
    path('', dashboard_views.clickhouse_logs_view, name='index'),
    path('logs/', dashboard_views.clickhouse_logs_view, name='clickhouse_logs'),
    path('top-summary/', dashboard_views.top_summary_view, name='top_summary'),
    path('grouped-logs/', grouped_logs_view, name='grouped_logs'),
    path('system-config/', dashboard_views.system_config_view, name='system_config'),
    path('log-sources/', dashboard_views.log_sources_view, name='log_sources'),
    path('log-management/', dashboard_views.log_management_status_view, name='log_management'),
    path('pa-url-logs/', dashboard_views.pa_url_logs_view, name='pa_url_logs'),
    path('url-summary/', dashboard_views.url_summary_view, name='url_summary'),
    path('uitest/', dashboard_views.uitest_view, name='uitest'),
    path('header-test/', dashboard_views.header_test_view, name='header_test'),
]
