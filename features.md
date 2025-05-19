net@edl:~$ ls -lh /var/log/fortigate.log*
-rw-r--r-- 1 syslog 988 12G May 19 14:35 /var/log/fortigate.log
net@edl:~$ clickhouse-client
ClickHouse client version 25.4.3.22 (official build).
Connecting to localhost:9000 as user default.
Password for user (default):
Connecting to localhost:9000 as user default.
Connected to ClickHouse server version 25.4.3.

Warnings:
 * Delay accounting is not enabled, OSIOWaitMicroseconds will not be gathered. You can enable it using `echo 1 > /proc/sys/kernel/task_delayacct` or by using sysctl.

edl :) USE network_logs;


USE network_logs

Query id: 7d2b8dc9-0a12-4d46-afef-2e758259d3f0

Ok.

0 rows in set. Elapsed: 0.003 sec.

edl :) DESCRIBE TABLE fortigate_traffic

DESCRIBE TABLE fortigate_traffic

Query id: 44517127-1ba3-4f92-94de-0df312ff6c78

    ┌─name──────────┬─type─────┬─default_type─┬─default_expression────────────────────┬─comment─┬─codec_expression─┬─ttl_expression─┐
 1. │ timestamp     │ DateTime │              │                                       │         │                  │                │
 2. │ raw_message   │ String   │              │                                       │         │                  │                │
 3. │ devname       │ String   │              │                                       │         │                  │                │
 4. │ devid         │ String   │              │                                       │         │                  │                │
 5. │ eventtime     │ UInt64   │              │                                       │         │                  │                │
 6. │ tz            │ String   │              │                                       │         │                  │                │
 7. │ logid         │ String   │              │                                       │         │                  │                │
 8. │ type          │ String   │              │                                       │         │                  │                │
 9. │ subtype       │ String   │              │                                       │         │                  │                │
10. │ level         │ String   │              │                                       │         │                  │                │
11. │ vd            │ String   │              │                                       │         │                  │                │
12. │ srcip         │ IPv4     │              │                                       │         │                  │                │
13. │ srcport       │ UInt16   │              │                                       │         │                  │                │
14. │ srcintf       │ String   │              │                                       │         │                  │                │
15. │ srcintfrole   │ String   │              │                                       │         │                  │                │
16. │ dstip         │ IPv4     │              │                                       │         │                  │                │
17. │ dstport       │ UInt16   │              │                                       │         │                  │                │
18. │ dstintf       │ String   │              │                                       │         │                  │                │
19. │ dstintfrole   │ String   │              │                                       │         │                  │                │
20. │ srccountry    │ String   │              │                                       │         │                  │                │
21. │ dstcountry    │ String   │              │                                       │         │                  │                │
22. │ sessionid     │ UInt64   │              │                                       │         │                  │                │
23. │ proto         │ UInt8    │              │                                       │         │                  │                │
24. │ action        │ String   │              │                                       │         │                  │                │
25. │ policyid      │ UInt32   │              │                                       │         │                  │                │
26. │ policytype    │ String   │              │                                       │         │                  │                │
27. │ poluuid       │ String   │              │                                       │         │                  │                │
28. │ policyname    │ String   │              │                                       │         │                  │                │
29. │ service       │ String   │              │                                       │         │                  │                │
30. │ trandisp      │ String   │              │                                       │         │                  │                │
31. │ appcat        │ String   │              │                                       │         │                  │                │
32. │ duration      │ UInt32   │              │                                       │         │                  │                │
33. │ sentbyte      │ UInt64   │              │                                       │         │                  │                │
34. │ rcvdbyte      │ UInt64   │              │                                       │         │                  │                │
35. │ sentpkt       │ UInt32   │              │                                       │         │                  │                │
36. │ rcvdpkt       │ UInt32   │              │                                       │         │                  │                │
37. │ sentdelta     │ UInt32   │              │                                       │         │                  │                │
38. │ rcvddelta     │ UInt32   │              │                                       │         │                  │                │
39. │ durationdelta │ UInt32   │              │                                       │         │                  │                │
40. │ sentpktdelta  │ UInt32   │              │                                       │         │                  │                │
41. │ rcvdpktdelta  │ UInt32   │              │                                       │         │                  │                │
42. │ vpntype       │ String   │              │                                       │         │                  │                │
43. │ log_date      │ Date     │ DEFAULT      │ toDate(timestamp)                     │         │                  │                │
44. │ log_time      │ String   │ DEFAULT      │ formatDateTime(timestamp, '%H:%M:%S') │         │                  │                │
    └───────────────┴──────────┴──────────────┴───────────────────────────────────────┴─────────┴──────────────────┴────────────────┘

44 rows in set. Elapsed: 0.001 sec.

edl :)
edl :)
edl :)
edl :)
edl :)
edl :)
edl :) SELECT *
FROM fortigate_traffic
ORDER BY timestamp DESC
LIMIT 5;


