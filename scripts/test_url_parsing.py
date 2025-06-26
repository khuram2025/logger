#!/usr/bin/env python3
"""
Test URL parsing with a sample log line
"""

from datetime import datetime
import json

# Sample URL log line from the file
sample_line = 'Jun 26 12:02:04 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/06/26 12:02:02,024301003410,THREAT,url,2817,2025/06/26 12:02:02,10.10.200.111,31.13.69.60,185.27.220.65,31.13.69.60,Close Social Media_WEB_Brwosing,smo\\a.alqadeeb,,whatsapp-web,vsys1,HQ_INT_CORE,OutSide_Mobily,ae1.2004,ethernet1/7,SMOEDL,2025/06/26 12:02:03,1356737,1,57931,443,61825,443,0x42b400,tcp,block-url,"web.whatsapp.com/",(9999),SMO_Block_URLs,informational,client-to-server,7508761568359533162,0x0,10.0.0.0-10.255.255.255,Italy,,,0,,,0,,,,,,,,0,210,14,0,0,,SMO-RUH-MU04-F09R14-INT-FW01,,,,,0,,0,,N/A,N/A,AppThreat-0-0,0x0,0,4294967295,," SMO_Exception_List,internet-communications-and-telephony,low-risk",7ef917ba-fdb6-45d3-b3b4-8df792316988,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2025-06-26T12:02:04.099+03:00,,,,instant-messaging,collaboration,browser-based,3,"has-known-vulnerability,pervasive-use,is-saas,is-pci",whatsapp,whatsapp-web,yes,no,,,NonProxyTraffic'

# Parse the line
parts = sample_line.split(' ', 4)
print(f"Parts count: {len(parts)}")
print(f"Device name: {parts[3] if len(parts) > 3 else 'N/A'}")

if len(parts) >= 5:
    log_data = parts[4]
    fields = log_data.split(',')
    print(f"\nTotal fields: {len(fields)}")
    print(f"Log type: {fields[3] if len(fields) > 3 else 'N/A'}")
    print(f"Log subtype: {fields[4] if len(fields) > 4 else 'N/A'}")
    
    if len(fields) > 31:
        print(f"\nField 31 (URL): {fields[31]}")
        print(f"Field 32 (Threat): {fields[32]}")
        print(f"Field 33 (Category): {fields[33]}")
        
    # Print field positions for key data
    print("\nKey field positions:")
    print(f"Timestamp (6): {fields[6] if len(fields) > 6 else 'N/A'}")
    print(f"Source IP (7): {fields[7] if len(fields) > 7 else 'N/A'}")
    print(f"Dest IP (8): {fields[8] if len(fields) > 8 else 'N/A'}")
    print(f"Source Port (24): {fields[24] if len(fields) > 24 else 'N/A'}")
    print(f"Dest Port (25): {fields[25] if len(fields) > 25 else 'N/A'}")
    print(f"Action (30): {fields[30] if len(fields) > 30 else 'N/A'}")
    
    # Count all fields
    print(f"\nAll fields ({len(fields)}):")
    for i, field in enumerate(fields[:40]):  # Show first 40 fields
        print(f"{i}: {field}")