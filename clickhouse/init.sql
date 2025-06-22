-- Create database if not exists
CREATE DATABASE IF NOT EXISTS network_logs;

USE network_logs;

-- FortiGate traffic table
CREATE TABLE IF NOT EXISTS fortigate_traffic (
    timestamp DateTime,
    srcip IPv4,
    dstip IPv4,
    srcport UInt16,
    dstport UInt16,
    action String,
    proto UInt8,
    rcvdbyte UInt64,
    sentbyte UInt64,
    sentpkt UInt32,
    rcvdpkt UInt32,
    duration UInt32,
    srcintf String,
    dstintf String,
    policyname String,
    username String,
    srccountry String,
    dstcountry String,
    devname String,
    logid String,
    url String,
    hostname String,
    appcategory String,
    raw_message String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, srcip, dstip)
TTL timestamp + INTERVAL 90 DAY;

-- PaloAlto traffic table
CREATE TABLE IF NOT EXISTS pa_traffic (
    timestamp DateTime,
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    action String,
    protocol UInt8,
    bytes_received UInt64,
    bytes_sent UInt64,
    packets_sent UInt32,
    packets_received UInt32,
    elapsed_time UInt32,
    device_name String,
    src_user String,
    dst_country String,
    application String,
    app_category String,
    rule_name String,
    threat_id String,
    severity String,
    raw_message String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 90 DAY;

-- Threat logs table
CREATE TABLE IF NOT EXISTS threat_logs (
    timestamp DateTime,
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    action String,
    threat_id String,
    threat_name String,
    severity String,
    category String,
    direction String,
    device_name String,
    user String,
    application String,
    raw_message String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY;

-- URL logs table
CREATE TABLE IF NOT EXISTS url_logs (
    timestamp DateTime,
    src_ip IPv4,
    dst_ip IPv4,
    user String,
    url String,
    category String,
    action String,
    device_name String,
    content_type String,
    referer String,
    user_agent String,
    method String,
    response_code UInt16,
    bytes_sent UInt64,
    bytes_received UInt64,
    raw_message String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, url)
TTL timestamp + INTERVAL 30 DAY;

-- Create indexes for better query performance
ALTER TABLE fortigate_traffic ADD INDEX idx_devname devname TYPE set(0) GRANULARITY 4;
ALTER TABLE pa_traffic ADD INDEX idx_device_name device_name TYPE set(0) GRANULARITY 4;
ALTER TABLE fortigate_traffic ADD INDEX idx_action action TYPE set(0) GRANULARITY 4;
ALTER TABLE pa_traffic ADD INDEX idx_action action TYPE set(0) GRANULARITY 4;