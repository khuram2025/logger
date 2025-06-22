from django.db import models
from django.utils import timezone
from django.core.validators import validate_ipv4_address
import json

class LogSource(models.Model):
    """Model for managing log sources with automatic detection and approval workflow"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
    ]
    
    DEVICE_TYPE_CHOICES = [
        ('unknown', 'Unknown Device'),
        ('fortigate', 'FortiGate Firewall'),
        ('paloalto', 'Palo Alto Firewall'),
        ('cisco', 'Cisco Device'),
        ('checkpoint', 'Check Point Firewall'),
        ('sophos', 'Sophos Firewall'),
        ('juniper', 'Juniper Device'),
        ('generic', 'Generic Syslog Device'),
    ]
    
    PROTOCOL_CHOICES = [
        ('udp', 'UDP'),
        ('tcp', 'TCP'),
    ]
    
    TEMPLATE_CHOICES = [
        ('raw', 'Raw Logs'),
        ('timestamp', 'Timestamped'),
        ('detailed', 'Detailed Format'),
        ('fortigate_default', 'FortiGate Default'),
        ('paloalto_default', 'PaloAlto Default'),
        ('custom', 'Custom Template'),
    ]
    
    # Basic Information
    name = models.CharField(max_length=100, help_text="Friendly name for this log source")
    description = models.TextField(blank=True, help_text="Optional description")
    ip_address = models.GenericIPAddressField(
        validators=[validate_ipv4_address],
        unique=True,
        help_text="Source IP address"
    )
    hostname = models.CharField(max_length=255, blank=True, help_text="Detected hostname")
    
    # Device Information
    device_type = models.CharField(
        max_length=20,
        choices=DEVICE_TYPE_CHOICES,
        default='unknown',
        help_text="Type of device sending logs"
    )
    device_model = models.CharField(max_length=100, blank=True, help_text="Device model if detected")
    device_version = models.CharField(max_length=50, blank=True, help_text="Device firmware/software version")
    
    # Network Configuration
    port = models.PositiveIntegerField(default=514, help_text="Port number for log reception")
    protocol = models.CharField(
        max_length=3,
        choices=PROTOCOL_CHOICES,
        default='udp',
        help_text="Protocol used for log transmission"
    )
    
    # Status and Workflow
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='pending',
        help_text="Current status in approval workflow"
    )
    
    # Log Processing Configuration
    save_logs = models.BooleanField(default=True, help_text="Enable log file saving")
    log_file_path = models.CharField(
        max_length=255,
        blank=True,
        help_text="Path where logs are saved"
    )
    log_template = models.CharField(
        max_length=20,
        choices=TEMPLATE_CHOICES,
        default='raw',
        help_text="Template used for log formatting"
    )
    custom_template = models.TextField(
        blank=True,
        help_text="Custom rsyslog template (when template=custom)"
    )
    parse_to_database = models.BooleanField(
        default=False,
        help_text="Enable parsing logs to ClickHouse database"
    )
    
    # Detection and Approval
    first_seen = models.DateTimeField(auto_now_add=True, help_text="When first detected")
    last_seen = models.DateTimeField(auto_now=True, help_text="Last log received")
    approved_by = models.CharField(max_length=100, blank=True, help_text="Who approved this source")
    approved_at = models.DateTimeField(null=True, blank=True, help_text="When approved")
    rejected_reason = models.TextField(blank=True, help_text="Reason for rejection")
    
    # Statistics
    total_logs = models.BigIntegerField(default=0, help_text="Total logs received")
    logs_today = models.IntegerField(default=0, help_text="Logs received today")
    logs_last_hour = models.IntegerField(default=0, help_text="Logs received in last hour")
    
    # Metadata
    configuration_data = models.JSONField(
        default=dict,
        help_text="Additional configuration data"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'log_sources'
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['status']),
            models.Index(fields=['device_type']),
            models.Index(fields=['last_seen']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.ip_address})"
    
    def approve(self, approved_by_user=None):
        """Approve this log source and activate it"""
        self.status = 'approved'
        self.approved_by = approved_by_user or 'system'
        self.approved_at = timezone.now()
        self.save()
        
        # Generate log file path if not set
        if not self.log_file_path:
            self.generate_log_file_path()
        
        # Auto-configure based on device type
        self.auto_configure_parser()
        
        return True
    
    def reject(self, reason=""):
        """Reject this log source"""
        self.status = 'rejected'
        self.rejected_reason = reason
        self.save()
        return True
    
    def activate(self):
        """Activate an approved log source"""
        if self.status == 'approved':
            self.status = 'active'
            self.save()
            return True
        return False
    
    def deactivate(self):
        """Deactivate a log source"""
        if self.status == 'active':
            self.status = 'inactive'
            self.save()
            return True
        return False
    
    def generate_log_file_path(self):
        """Generate appropriate log file path based on device type"""
        if self.device_type == 'fortigate':
            self.log_file_path = f"/var/log/fortigate-{self.ip_address.replace('.', '-')}.log"
        elif self.device_type == 'paloalto':
            self.log_file_path = f"/var/log/paloalto-{self.ip_address.replace('.', '-')}.log"
        else:
            safe_name = self.name.lower().replace(' ', '-').replace('_', '-')
            self.log_file_path = f"/var/log/{safe_name}-{self.ip_address.replace('.', '-')}.log"
        self.save()
    
    def auto_configure_parser(self):
        """Auto-configure parser settings based on device type"""
        if self.device_type == 'fortigate':
            self.log_template = 'fortigate_default'
            self.parse_to_database = True
        elif self.device_type == 'paloalto':
            self.log_template = 'paloalto_default'
            self.parse_to_database = True
        else:
            self.log_template = 'timestamp'
            self.parse_to_database = False
        self.save()
    
    def update_stats(self, logs_count=1):
        """Update log statistics"""
        self.total_logs += logs_count
        self.last_seen = timezone.now()
        self.save(update_fields=['total_logs', 'last_seen'])
    
    def get_rsyslog_config(self):
        """Generate rsyslog configuration for this source"""
        template_name = f"Template_{self.name.replace(' ', '_')}"
        
        # Choose template based on type
        if self.log_template == 'fortigate_default':
            template_def = 'template(name="{}" type="string" string="%rawmsg-after-pri%\\n")'.format(template_name)
        elif self.log_template == 'paloalto_default':
            template_def = 'template(name="{}" type="string" string="%rawmsg-after-pri%\\n")'.format(template_name)
        elif self.log_template == 'timestamp':
            template_def = 'template(name="{}" type="string" string="%timestamp% %rawmsg-after-pri%\\n")'.format(template_name)
        elif self.log_template == 'custom' and self.custom_template:
            template_def = self.custom_template
        else:
            template_def = 'template(name="{}" type="string" string="%rawmsg-after-pri%\\n")'.format(template_name)
        
        config = f"""# Configuration for {self.name} ({self.ip_address})
{template_def}
if ($fromhost-ip == '{self.ip_address}') then {{
    action(type="omfile" file="{self.log_file_path}" template="{template_name}")
    stop
}}
"""
        return config
    
    @classmethod
    def detect_or_create(cls, ip_address, hostname=None, sample_log=None):
        """Detect device type from log sample and create/update log source"""
        # Try to get existing source
        source, created = cls.objects.get_or_create(
            ip_address=ip_address,
            defaults={
                'name': hostname or f"Device-{ip_address}",
                'hostname': hostname or '',
                'status': 'pending'
            }
        )
        
        # Update last seen
        source.last_seen = timezone.now()
        
        # Try to detect device type from log sample
        if sample_log and source.device_type == 'unknown':
            detected_type = cls.detect_device_type(sample_log)
            if detected_type != 'unknown':
                source.device_type = detected_type
                # Update name if it was generic
                if source.name.startswith('Device-'):
                    source.name = f"{detected_type.title()}-{ip_address}"
        
        source.save()
        return source, created
    
    @staticmethod
    def detect_device_type(log_sample):
        """Detect device type from log sample"""
        if not log_sample:
            return 'unknown'
        
        log_lower = log_sample.lower()
        
        # FortiGate detection
        if any(keyword in log_lower for keyword in ['fortigate', 'fortios', 'logid=', 'devname=']):
            return 'fortigate'
        
        # Palo Alto detection
        if any(keyword in log_lower for keyword in ['palo alto', 'pan-os', ',1,', 'traffic,1,']):
            return 'paloalto'
        
        # Cisco detection
        if any(keyword in log_lower for keyword in ['cisco', '%asa-', '%fwsm-', '%pix-']):
            return 'cisco'
        
        # Check Point detection
        if any(keyword in log_lower for keyword in ['checkpoint', 'splat', 'fw-1']):
            return 'checkpoint'
        
        # Sophos detection
        if any(keyword in log_lower for keyword in ['sophos', 'cyberoam']):
            return 'sophos'
        
        # Juniper detection
        if any(keyword in log_lower for keyword in ['juniper', 'junos', 'srx']):
            return 'juniper'
        
        return 'unknown'


class LogSourceEvent(models.Model):
    """Track events related to log sources"""
    
    EVENT_TYPE_CHOICES = [
        ('detected', 'Device Detected'),
        ('approved', 'Source Approved'),
        ('rejected', 'Source Rejected'),
        ('activated', 'Source Activated'),
        ('deactivated', 'Source Deactivated'),
        ('configured', 'Configuration Updated'),
        ('error', 'Error Occurred'),
    ]
    
    log_source = models.ForeignKey(
        LogSource,
        on_delete=models.CASCADE,
        related_name='events'
    )
    event_type = models.CharField(max_length=20, choices=EVENT_TYPE_CHOICES)
    description = models.TextField(help_text="Event description")
    user = models.CharField(max_length=100, blank=True, help_text="User who triggered the event")
    metadata = models.JSONField(default=dict, help_text="Additional event data")
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'log_source_events'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['log_source', 'timestamp']),
            models.Index(fields=['event_type']),
        ]
    
    def __str__(self):
        return f"{self.log_source.name} - {self.get_event_type_display()}"


class ParserTemplate(models.Model):
    """Define parser templates for different device types"""
    
    name = models.CharField(max_length=100, unique=True)
    device_type = models.CharField(max_length=20, choices=LogSource.DEVICE_TYPE_CHOICES)
    description = models.TextField(help_text="Template description")
    
    # Rsyslog Configuration
    rsyslog_template = models.TextField(help_text="Rsyslog template definition")
    
    # Parser Configuration
    parser_script = models.CharField(
        max_length=255,
        help_text="Python script for parsing (e.g., enhanced_fortigate_to_clickhouse.py)"
    )
    clickhouse_table = models.CharField(
        max_length=100,
        help_text="ClickHouse table name"
    )
    
    # Sample Data
    sample_log = models.TextField(blank=True, help_text="Sample log for testing")
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'parser_templates'
        ordering = ['device_type', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.get_device_type_display()})"