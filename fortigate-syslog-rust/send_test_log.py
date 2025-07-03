#!/usr/bin/env python3
import socket
import time

# Test log from 10.10.100.2
test_log = b"<14>Jul  3 15:11:17 SMO-RUH-MU04-F09R14-DC-FW1.smo.sa 1,2025/07/03 15:11:17,025201005457,TRAFFIC,end,2817,2025/07/03 15:11:17,10.10.200.15,103.235.46.102,0.0.0.0,0.0.0.0,Allow Internet Trrafic,smo\\a.alhejaili,,ping,vsys1,SMO-WIFI-EMPLOYEE,HQ_DC_CORE,ae1.201,ae1.2004,H_SMO_LFP,2025/07/03 15:11:17,646044,1,0,0,0,0,0x100019,icmp,allow,110,110,0,1,2025/07/03 15:11:09,0,any,,7502587801702064241,0x8000000000000000,10.0.0.0-10.255.255.255,Hong Kong,,1,0,aged-out,210,70,0,0,,SMO-RUH-MU04-F09R14-DC-FW1,from-policy,,,0,,0,,N/A,0,0,0,0,ce9269f2-931f-47b0-8553-a7bc9ed91e93,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-07-03T15:11:17.571+03:00,,,internet-utility,general-internet,network-protocol,2,\"has-known-vulnerability,tunnel-other-application,pervasive-use\",,untunneled,no,no,0,NonProxyTraffic,"

print("Sending test log to port 5514...")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# We need to send this from the correct source IP
# Since we can't spoof, let's send directly to 5514
try:
    sock.sendto(test_log, ('localhost', 5514))
    print("✓ Sent test log")
except Exception as e:
    print(f"✗ Failed to send log: {e}")

sock.close()

print("\nNow check: sudo clickhouse-client --password='Read@123' -q \"SELECT count(*) FROM network_logs.fortigate_traffic WHERE raw_message LIKE '%7502587801702064241%' FORMAT Pretty\"")