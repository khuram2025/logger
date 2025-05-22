from django.urls import path
from . import views
from .views import SystemConfigView, PolicyTuningView # Import PolicyTuningView

urlpatterns = [
    path('dmu/', views.dmu_view, name='dmu'),
    path('logs/', views.clickhouse_logs_view, name='clickhouse_logs'),
    path('top-summary/', views.top_summary_view, name='top_summary'),
    path('system-config/', SystemConfigView.as_view(), name='system_config'),
    path('policy-tuning/', PolicyTuningView.as_view(), name='policy_tuning'), # Add new URL pattern
]
