#!/usr/bin/env python3
"""
Cleanup Pending Log Sources
Remove incorrectly created pending log sources, keeping only actual devices.
"""

import os
import sys
import django

# Add the project root to Python path
sys.path.append('/home/net/analyzer')

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fwanalyzer.settings')
django.setup()

from dashboard.models import LogSource
from datetime import datetime

def cleanup_pending_sources():
    """
    Remove all pending log sources except the 3 actual devices:
    - 192.168.100.221 (FortiGate)
    - 10.10.100.2 (PaloAlto)
    - 10.10.100.4 (PaloAlto)
    """
    
    # The actual log source devices from rsyslog configs
    actual_devices = {
        '192.168.100.221',  # FortiGate
        '10.10.100.2',      # PaloAlto
        '10.10.100.4'       # PaloAlto
    }
    
    print("🧹 Starting cleanup of pending log sources...")
    
    # Get all log sources
    all_sources = LogSource.objects.all()
    print(f"Total log sources in database: {all_sources.count()}")
    
    # Find pending sources
    pending_sources = LogSource.objects.filter(status='pending')
    print(f"Pending log sources: {pending_sources.count()}")
    
    if pending_sources.count() == 0:
        print("✅ No pending sources to clean up")
        return
    
    # Separate actual devices from incorrectly detected ones
    actual_pending = []
    incorrect_pending = []
    
    for source in pending_sources:
        if source.ip_address in actual_devices:
            actual_pending.append(source)
            print(f"✅ Keeping actual device: {source.ip_address} ({source.device_type})")
        else:
            incorrect_pending.append(source)
    
    print(f"\nFound {len(actual_pending)} actual devices in pending state")
    print(f"Found {len(incorrect_pending)} incorrectly detected sources to remove")
    
    if incorrect_pending:
        print(f"\n🗑️  Removing {len(incorrect_pending)} incorrect sources...")
        
        # Show some examples of what will be deleted
        print("Examples of sources being removed:")
        for i, source in enumerate(incorrect_pending[:10]):
            print(f"  - {source.ip_address} ({source.device_type})")
            if i == 9 and len(incorrect_pending) > 10:
                print(f"  ... and {len(incorrect_pending) - 10} more")
        
        # Delete the incorrect sources
        deleted_count, _ = LogSource.objects.filter(
            id__in=[s.id for s in incorrect_pending]
        ).delete()
        
        print(f"✅ Successfully removed {deleted_count} incorrect pending sources")
    
    # Update actual devices to 'active' status if they have recent activity
    if actual_pending:
        print(f"\n🔄 Updating status of actual devices...")
        for source in actual_pending:
            # Set to active since these are the real devices from rsyslog config
            source.status = 'active'
            source.last_seen = datetime.now()
            source.save()
            print(f"✅ Updated {source.ip_address} to active status")
    
    # Final summary
    final_sources = LogSource.objects.all()
    pending_final = LogSource.objects.filter(status='pending')
    active_final = LogSource.objects.filter(status='active')
    
    print(f"\n📊 Final Summary:")
    print(f"Total log sources: {final_sources.count()}")
    print(f"Active sources: {active_final.count()}")
    print(f"Pending sources: {pending_final.count()}")
    
    if active_final.count() > 0:
        print(f"\nActive devices:")
        for source in active_final:
            print(f"  🟢 {source.ip_address} ({source.device_type})")
    
    if pending_final.count() > 0:
        print(f"\nRemaining pending devices:")
        for source in pending_final:
            print(f"  🟡 {source.ip_address} ({source.device_type})")

if __name__ == "__main__":
    cleanup_pending_sources()