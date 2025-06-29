#!/usr/bin/env python3
import socket
import time

# Test sending a FortiGate-formatted syslog message
message = '<189>date=2025-06-29 time=15:00:00 devname="TEST-FW" devid="TEST123" eventtime=1751197327173386538 tz="+0300" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.1 srcport=12345 srcintf="port1" srcintfrole="lan" dstip=8.8.8.8 dstport=443 dstintf="port2" dstintfrole="wan" srccountry="Reserved" dstcountry="Reserved" sessionid=12345 proto=6 action="accept" policyid=1 policytype="policy" poluuid="test-uuid" policyname="Test Policy" service="HTTPS" trandisp="noop" appcat="unscanned" duration=10 sentbyte=1000 rcvdbyte=5000 sentpkt=10 rcvdpkt=20'

# Test port 5514 (non-privileged)
print("Testing UDP port 5514...")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(message.encode(), ('localhost', 5514))
    print("✓ Message sent to port 5514")
except Exception as e:
    print(f"✗ Failed to send to port 5514: {e}")
finally:
    sock.close()

# Test port 514 (should work with iptables redirect)
print("\nTesting UDP port 514 (requires iptables redirect)...")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(message.encode(), ('localhost', 514))
    print("✓ Message sent to port 514")
except Exception as e:
    print(f"✗ Failed to send to port 514: {e}")
finally:
    sock.close()