#!/usr/bin/env python3
"""
Debug script to test if logs from 10.10.100.6 are actually reaching the service
"""
import socket
import time

# Test log from 10.10.100.6 based on the sample file
test_log = 'Jul  1 14:57:30 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/07/01 14:57:29,024301003410,THREAT,url,2817,2025/07/01 14:57:29,10.10.200.163,95.101.35.56,185.27.220.65,95.101.35.56,Close Social Media_WEB_Brwosing,,,web-browsing,vsys1,HQ_INT_CORE,OutSide_Mobily,ae1.2004,ethernet1/7,SMOEDL,2025/07/01 14:57:30,748474,1,54899,80,18588,80,0x42b000,tcp,alert,"www.msftconnecttest.com/connecttest.txt",(9999),computer-and-internet-info,informational,client-to-server,7508761568363282988,0x0,10.0.0.0-10.255.255.255,Italy,,text/plain,0,,,1,Microsoft NCSI,,,,,,,0,210,14,0,0,,SMO-RUH-MU04-F09R14-INT-FW01,,,,get,0,,0,,N/A,N/A,AppThreat-0-0,0x0,0,4294967295,,"computer-and-internet-info,low-risk",7ef917ba-fdb6-45d3-b3b4-8df792316988,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2025-07-01T14:57:30.481+03:00,,,,internet-utility,general-internet,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,web-browsing,no,no,,,NonProxyTraffic'

def test_syslog_reception():
    """Test if we can send a log and see if it's processed"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Send from a different source first to confirm it works
    print("Testing with log sample...")
    
    try:
        # Test with the actual log format
        sock.sendto(test_log.encode('utf-8'), ('127.0.0.1', 5514))
        print("✓ Sent test log successfully")
        time.sleep(2)
        
        # Send a simplified version
        simple_log = '1,2025/07/01 14:57:29,024301003410,THREAT,url,2817,2025/07/01 14:57:29,10.10.200.163,95.101.35.56,185.27.220.65,95.101.35.56,test_rule,,,web-browsing,vsys1,inside,outside,ae1.2004,ethernet1/7,SMOEDL,2025/07/01 14:57:30,748474,1,54899,80,18588,80,0x42b000,tcp,alert,"test.com",(9999),malware,critical,client-to-server,123456,0x0,10.0.0.0-10.255.255.255,US,,text/html'
        sock.sendto(simple_log.encode('utf-8'), ('127.0.0.1', 5514))
        print("✓ Sent simplified test log")
        
    except Exception as e:
        print(f"✗ Error sending log: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    test_syslog_reception()