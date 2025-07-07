"""
Network Topology Management Views

This module contains all views related to network topology management including
device zones, subnets, and interfaces management.
"""

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.forms.models import model_to_dict
from django.db import transaction
from django.http import JsonResponse

from ..models import (
    LogSource, DeviceZone, DeviceSubnet, DeviceInterface, 
    NetworkTopologySnapshot
)


# ============================================================================
# Network Topology Management Views
# ============================================================================

def device_topology_view(request, device_id):
    """Main network topology management view for a device"""
    device = get_object_or_404(LogSource, id=device_id)
    
    # Get all topology components
    zones = device.zones.filter(is_active=True).order_by('security_level', 'name')
    subnets = device.subnets.filter(is_active=True).order_by('zone', 'name')
    interfaces = device.interfaces.filter(is_active=True).order_by('name')
    
    # Get zone statistics
    zone_stats = {}
    for zone in zones:
        zone_stats[zone.id] = {
            'subnets_count': zone.subnets.filter(is_active=True).count(),
            'interfaces_count': zone.interfaces.filter(is_active=True).count(),
        }
    
    # Get recent topology changes
    recent_snapshots = device.topology_snapshots.all()[:5]
    
    context = {
        'device': device,
        'zones': zones,
        'subnets': subnets,
        'interfaces': interfaces,
        'zone_stats': zone_stats,
        'recent_snapshots': recent_snapshots,
        'tab': 'topology'
    }
    
    return render(request, 'dashboard/device_topology.html', context)


def device_zones_view(request, device_id):
    """Manage zones for a device"""
    device = get_object_or_404(LogSource, id=device_id)
    zones = device.zones.all().order_by('security_level', 'name')
    
    context = {
        'device': device,
        'zones': zones,
        'tab': 'zones'
    }
    
    return render(request, 'dashboard/device_zones.html', context)


def add_zone_view(request, device_id):
    """Add a new zone to a device"""
    device = get_object_or_404(LogSource, id=device_id)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                zone = DeviceZone.objects.create(
                    device=device,
                    name=request.POST.get('name'),
                    zone_type=request.POST.get('zone_type', 'custom'),
                    description=request.POST.get('description', ''),
                    security_level=int(request.POST.get('security_level', 50)),
                    allow_inter_zone=request.POST.get('allow_inter_zone') == 'on'
                )
                
                messages.success(request, f'Zone "{zone.name}" created successfully.')
                return redirect('device_zones', device_id=device.id)
                
        except Exception as e:
            messages.error(request, f'Error creating zone: {str(e)}')
    
    context = {
        'device': device,
        'zone_types': DeviceZone.ZONE_TYPE_CHOICES,
        'security_levels': DeviceZone.SECURITY_LEVEL_CHOICES,
        'tab': 'zones'
    }
    
    return render(request, 'dashboard/add_zone.html', context)


def edit_zone_view(request, zone_id):
    """Edit an existing zone"""
    zone = get_object_or_404(DeviceZone, id=zone_id)
    device = zone.device
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                zone.name = request.POST.get('name')
                zone.zone_type = request.POST.get('zone_type', 'custom')
                zone.description = request.POST.get('description', '')
                zone.security_level = int(request.POST.get('security_level', 50))
                zone.allow_inter_zone = request.POST.get('allow_inter_zone') == 'on'
                zone.is_active = request.POST.get('is_active') == 'on'
                zone.save()
                
                messages.success(request, f'Zone "{zone.name}" updated successfully.')
                return redirect('device_zones', device_id=device.id)
                
        except Exception as e:
            messages.error(request, f'Error updating zone: {str(e)}')
    
    context = {
        'device': device,
        'zone': zone,
        'zone_types': DeviceZone.ZONE_TYPE_CHOICES,
        'security_levels': DeviceZone.SECURITY_LEVEL_CHOICES,
        'tab': 'zones'
    }
    
    return render(request, 'dashboard/edit_zone.html', context)


def delete_zone_view(request, zone_id):
    """Delete a zone"""
    zone = get_object_or_404(DeviceZone, id=zone_id)
    device = zone.device
    
    if request.method == 'POST':
        try:
            zone_name = zone.name
            zone.delete()
            messages.success(request, f'Zone "{zone_name}" deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting zone: {str(e)}')
    
    return redirect('device_zones', device_id=device.id)


def device_subnets_view(request, device_id):
    """Manage subnets for a device"""
    device = get_object_or_404(LogSource, id=device_id)
    subnets = device.subnets.all().order_by('zone', 'name')
    
    context = {
        'device': device,
        'subnets': subnets,
        'tab': 'subnets'
    }
    
    return render(request, 'dashboard/device_subnets.html', context)


def add_subnet_view(request, device_id):
    """Add a new subnet to a device"""
    device = get_object_or_404(LogSource, id=device_id)
    zones = device.zones.filter(is_active=True).order_by('security_level', 'name')
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                subnet_data = {
                    'device': device,
                    'name': request.POST.get('name'),
                    'network_address': request.POST.get('network_address'),
                    'subnet_type': request.POST.get('subnet_type', 'custom'),
                    'description': request.POST.get('description', ''),
                    'gateway': request.POST.get('gateway') or None,
                    'vlan_id': int(request.POST.get('vlan_id')) if request.POST.get('vlan_id') else None,
                    'monitor_traffic': request.POST.get('monitor_traffic') == 'on',
                }
                
                # Add zone if selected
                zone_id = request.POST.get('zone')
                if zone_id:
                    subnet_data['zone'] = get_object_or_404(DeviceZone, id=zone_id)
                
                subnet = DeviceSubnet.objects.create(**subnet_data)
                
                messages.success(request, f'Subnet "{subnet.name}" created successfully.')
                return redirect('device_subnets', device_id=device.id)
                
        except Exception as e:
            messages.error(request, f'Error creating subnet: {str(e)}')
    
    context = {
        'device': device,
        'zones': zones,
        'subnet_types': DeviceSubnet.SUBNET_TYPE_CHOICES,
        'tab': 'subnets'
    }
    
    return render(request, 'dashboard/add_subnet.html', context)


def edit_subnet_view(request, subnet_id):
    """Edit an existing subnet"""
    subnet = get_object_or_404(DeviceSubnet, id=subnet_id)
    device = subnet.device
    zones = device.zones.filter(is_active=True).order_by('security_level', 'name')
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                subnet.name = request.POST.get('name')
                subnet.network_address = request.POST.get('network_address')
                subnet.subnet_type = request.POST.get('subnet_type', 'custom')
                subnet.description = request.POST.get('description', '')
                subnet.gateway = request.POST.get('gateway') or None
                subnet.vlan_id = int(request.POST.get('vlan_id')) if request.POST.get('vlan_id') else None
                subnet.monitor_traffic = request.POST.get('monitor_traffic') == 'on'
                subnet.is_active = request.POST.get('is_active') == 'on'
                
                # Update zone
                zone_id = request.POST.get('zone')
                if zone_id:
                    subnet.zone = get_object_or_404(DeviceZone, id=zone_id)
                else:
                    subnet.zone = None
                
                subnet.save()
                
                messages.success(request, f'Subnet "{subnet.name}" updated successfully.')
                return redirect('device_subnets', device_id=device.id)
                
        except Exception as e:
            messages.error(request, f'Error updating subnet: {str(e)}')
    
    context = {
        'device': device,
        'subnet': subnet,
        'zones': zones,
        'subnet_types': DeviceSubnet.SUBNET_TYPE_CHOICES,
        'tab': 'subnets'
    }
    
    return render(request, 'dashboard/edit_subnet.html', context)


def delete_subnet_view(request, subnet_id):
    """Delete a subnet"""
    subnet = get_object_or_404(DeviceSubnet, id=subnet_id)
    device = subnet.device
    
    if request.method == 'POST':
        try:
            subnet_name = subnet.name
            subnet.delete()
            messages.success(request, f'Subnet "{subnet_name}" deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting subnet: {str(e)}')
    
    return redirect('device_subnets', device_id=device.id)


def device_interfaces_view(request, device_id):
    """Manage interfaces for a device"""
    device = get_object_or_404(LogSource, id=device_id)
    interfaces = device.interfaces.all().order_by('name')
    
    context = {
        'device': device,
        'interfaces': interfaces,
        'tab': 'interfaces'
    }
    
    return render(request, 'dashboard/device_interfaces.html', context)


def add_interface_view(request, device_id):
    """Add a new interface to a device"""
    device = get_object_or_404(LogSource, id=device_id)
    zones = device.zones.filter(is_active=True).order_by('security_level', 'name')
    subnets = device.subnets.filter(is_active=True).order_by('zone', 'name')
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                interface_data = {
                    'device': device,
                    'name': request.POST.get('name'),
                    'alias': request.POST.get('alias', ''),
                    'interface_type': request.POST.get('interface_type', 'ethernet'),
                    'ip_address': request.POST.get('ip_address') or None,
                    'subnet_mask': request.POST.get('subnet_mask', ''),
                    'cidr_prefix': int(request.POST.get('cidr_prefix')) if request.POST.get('cidr_prefix') else None,
                    'mac_address': request.POST.get('mac_address', ''),
                    'speed': request.POST.get('speed', 'auto'),
                    'duplex': request.POST.get('duplex', 'auto'),
                    'mtu': int(request.POST.get('mtu', 1500)),
                    'vlan_id': int(request.POST.get('vlan_id')) if request.POST.get('vlan_id') else None,
                    'native_vlan': int(request.POST.get('native_vlan')) if request.POST.get('native_vlan') else None,
                    'status': request.POST.get('status', 'unknown'),
                    'is_management': request.POST.get('is_management') == 'on',
                    'monitor_traffic': request.POST.get('monitor_traffic') == 'on',
                    'description': request.POST.get('description', ''),
                }
                
                # Add zone if selected
                zone_id = request.POST.get('zone')
                if zone_id:
                    interface_data['zone'] = get_object_or_404(DeviceZone, id=zone_id)
                
                interface = DeviceInterface.objects.create(**interface_data)
                
                # Add selected subnets
                subnet_ids = request.POST.getlist('subnets')
                if subnet_ids:
                    interface.subnets.set(subnet_ids)
                
                messages.success(request, f'Interface "{interface.name}" created successfully.')
                return redirect('device_interfaces', device_id=device.id)
                
        except Exception as e:
            messages.error(request, f'Error creating interface: {str(e)}')
    
    context = {
        'device': device,
        'zones': zones,
        'subnets': subnets,
        'interface_types': DeviceInterface.INTERFACE_TYPE_CHOICES,
        'interface_statuses': DeviceInterface.INTERFACE_STATUS_CHOICES,
        'duplex_choices': DeviceInterface.DUPLEX_CHOICES,
        'speed_choices': DeviceInterface.SPEED_CHOICES,
        'tab': 'interfaces'
    }
    
    return render(request, 'dashboard/add_interface.html', context)


def edit_interface_view(request, interface_id):
    """Edit an existing interface"""
    interface = get_object_or_404(DeviceInterface, id=interface_id)
    device = interface.device
    zones = device.zones.filter(is_active=True).order_by('security_level', 'name')
    subnets = device.subnets.filter(is_active=True).order_by('zone', 'name')
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                interface.name = request.POST.get('name')
                interface.alias = request.POST.get('alias', '')
                interface.interface_type = request.POST.get('interface_type', 'ethernet')
                interface.ip_address = request.POST.get('ip_address') or None
                interface.subnet_mask = request.POST.get('subnet_mask', '')
                interface.cidr_prefix = int(request.POST.get('cidr_prefix')) if request.POST.get('cidr_prefix') else None
                interface.mac_address = request.POST.get('mac_address', '')
                interface.speed = request.POST.get('speed', 'auto')
                interface.duplex = request.POST.get('duplex', 'auto')
                interface.mtu = int(request.POST.get('mtu', 1500))
                interface.vlan_id = int(request.POST.get('vlan_id')) if request.POST.get('vlan_id') else None
                interface.native_vlan = int(request.POST.get('native_vlan')) if request.POST.get('native_vlan') else None
                interface.status = request.POST.get('status', 'unknown')
                interface.is_management = request.POST.get('is_management') == 'on'
                interface.monitor_traffic = request.POST.get('monitor_traffic') == 'on'
                interface.is_active = request.POST.get('is_active') == 'on'
                interface.description = request.POST.get('description', '')
                
                # Update zone
                zone_id = request.POST.get('zone')
                if zone_id:
                    interface.zone = get_object_or_404(DeviceZone, id=zone_id)
                else:
                    interface.zone = None
                
                interface.save()
                
                # Update selected subnets
                subnet_ids = request.POST.getlist('subnets')
                interface.subnets.set(subnet_ids)
                
                messages.success(request, f'Interface "{interface.name}" updated successfully.')
                return redirect('device_interfaces', device_id=device.id)
                
        except Exception as e:
            messages.error(request, f'Error updating interface: {str(e)}')
    
    context = {
        'device': device,
        'interface': interface,
        'zones': zones,
        'subnets': subnets,
        'interface_types': DeviceInterface.INTERFACE_TYPE_CHOICES,
        'interface_statuses': DeviceInterface.INTERFACE_STATUS_CHOICES,
        'duplex_choices': DeviceInterface.DUPLEX_CHOICES,
        'speed_choices': DeviceInterface.SPEED_CHOICES,
        'tab': 'interfaces'
    }
    
    return render(request, 'dashboard/edit_interface.html', context)


def delete_interface_view(request, interface_id):
    """Delete an interface"""
    interface = get_object_or_404(DeviceInterface, id=interface_id)
    device = interface.device
    
    if request.method == 'POST':
        try:
            interface_name = interface.name
            interface.delete()
            messages.success(request, f'Interface "{interface_name}" deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting interface: {str(e)}')
    
    return redirect('device_interfaces', device_id=device.id)


# ============================================================================
# AJAX Views for Dynamic Loading
# ============================================================================

def ajax_device_zones(request, device_id):
    """AJAX endpoint to get zones for a device"""
    device = get_object_or_404(LogSource, id=device_id)
    zones = device.zones.filter(is_active=True).order_by('security_level', 'name')
    
    zones_data = []
    for zone in zones:
        zones_data.append({
            'id': zone.id,
            'name': zone.name,
            'zone_type': zone.zone_type,
            'security_level': zone.security_level,
        })
    
    return JsonResponse({'zones': zones_data})


def ajax_device_subnets(request, device_id):
    """AJAX endpoint to get subnets for a device"""
    device = get_object_or_404(LogSource, id=device_id)
    subnets = device.subnets.filter(is_active=True).order_by('zone', 'name')
    
    subnets_data = []
    for subnet in subnets:
        subnets_data.append({
            'id': subnet.id,
            'name': subnet.name,
            'network_address': subnet.network_address,
            'subnet_type': subnet.subnet_type,
            'zone_id': subnet.zone.id if subnet.zone else None,
            'zone_name': subnet.zone.name if subnet.zone else None,
        })
    
    return JsonResponse({'subnets': subnets_data})


def ajax_zone_subnets(request, zone_id):
    """AJAX endpoint to get subnets for a specific zone"""
    zone = get_object_or_404(DeviceZone, id=zone_id)
    subnets = zone.subnets.filter(is_active=True).order_by('name')
    
    subnets_data = []
    for subnet in subnets:
        subnets_data.append({
            'id': subnet.id,
            'name': subnet.name,
            'network_address': subnet.network_address,
            'subnet_type': subnet.subnet_type,
        })
    
    return JsonResponse({'subnets': subnets_data})