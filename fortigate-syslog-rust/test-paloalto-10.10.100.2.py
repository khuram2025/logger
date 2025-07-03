#!/usr/bin/env python3
import socket
import time

# Exact log format from tcpdump for 10.10.100.2
test_logs = [
    '<14>Jul  3 13:40:32 SMO-RUH-MU04-F09R14-DC-FW1.smo.sa 1,2025/07/03 13:40:31,025201005457,TRAFFIC,drop,2817,2025/07/03 13:40:31,10.10.200.195,10.10.108.21,0.0.0.0,0.0.0.0,Deny_Ping_Traceroute_RDP,smo\\n.balilah,,ping,vsys1,SMO-WIFI-EMPLOYEE,SERVER,ae1.201,,H_SMO_LFP,2025/07/03 13:40:31,0,1,0,0,2048,0,0x100000,icmp,deny,62,62,0,1,2025/07/03 13:40:31,0,any,,7502587801700630623,0x8000000000000000,10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,,1,0,policy-deny,210,70,0,0,,SMO-RUH-MU04-F09R14-DC-FW1,from-policy,,,0,,0,,N/A,0,0,0,0,f4ff0be8-169a-4fa0-a7b2-f29bf451824c,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-07-03T13:40:32.826+03:00,,,internet-utility,general-internet,network-protocol,2,"has-known-vulnerability,tunnel-other-application,pervasive-use",,untunneled,no,no,0,NonProxyTraffic,',
    '<14>Jul  3 13:40:32 SMO-RUH-MU04-F09R14-DC-FW1.smo.sa 1,2025/07/03 13:40:31,025201005457,TRAFFIC,end,2817,2025/07/03 13:40:31,10.10.108.20,8.8.4.4,0.0.0.0,0.0.0.0,Allow Internet Trrafic,,,dns-base,vsys1,SERVER,HQ_DC_CORE,ae3.108,ae1.2004,H_SMO_LFP,2025/07/03 13:40:31,4557910,1,61940,53,0,0,0x19,udp,allow,256,100,156,2,2025/07/03 13:40:01,0,any,,7502587801700630627,0x8000000000000000,10.0.0.0-10.255.255.255,United States,,1,1,aged-out,210,70,0,0,,SMO-RUH-MU04-F09R14-DC-FW1,from-policy,,,0,,0,,N/A,0,0,0,0,ce9269f2-931f-47b0-8553-a7bc9ed91e93,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-07-03T13:40:32.826+03:00,,,infrastructure,networking,network-protocol,3,"used-by-malware,has-known-vulnerability,pervasive-use",dns,dns-base,no,no,0,NonProxyTraffic,'
]

print("Testing PaloAlto logs from 10.10.100.2 to port 5514...")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

for i, log in enumerate(test_logs):
    try:
        # Send as if coming from 10.10.100.2
        sock.sendto(log.encode(), ('localhost', 5514))
        print(f"✓ Sent test log {i+1}")
    except Exception as e:
        print(f"✗ Failed to send log {i+1}: {e}")
    time.sleep(0.1)

sock.close()
print("\nCheck the service logs to see if these were processed correctly.")