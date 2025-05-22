from django.db import models

class RsyslogHost(models.Model):
    address = models.GenericIPAddressField(
        unique=True,
        help_text="IP address allowed to send logs."
    )

    def __str__(self):
        return self.address

class LogRetentionPolicy(models.Model):
    INTERVAL_CHOICES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]

    enabled = models.BooleanField(default=True)
    interval = models.CharField(
        max_length=10,
        choices=INTERVAL_CHOICES,
        default='daily'
    )
    max_size = models.CharField(
        max_length=10,
        blank=True,
        null=True,
        help_text="e.g., 100M, 1G. Leave blank if no size limit."
    )
    keep_rotations = models.PositiveIntegerField(
        default=7,
        help_text="Number of log rotations to keep."
    )

    def __str__(self):
        return f"Log Retention Policy ({self.get_interval_display()})"
