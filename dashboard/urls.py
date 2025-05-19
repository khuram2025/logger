from django.urls import path
from . import views

urlpatterns = [
   
    path('dmu/', views.dmu_view, name='dmu'),
    path('logs/', views.clickhouse_logs_view, name='clickhouse_logs'),
]
