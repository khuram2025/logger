from django.contrib import admin
from .models import RsyslogHost, LogRetentionPolicy

@admin.register(RsyslogHost)
class RsyslogHostAdmin(admin.ModelAdmin):
    list_display = ('address',)
    search_fields = ('address',)

@admin.register(LogRetentionPolicy)
class LogRetentionPolicyAdmin(admin.ModelAdmin):
    list_display = ('interval', 'enabled', 'max_size', 'keep_rotations')
    list_filter = ('enabled', 'interval')
