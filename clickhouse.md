
-- Available tables in network_logs database:
-- 1. network_logs.fortigate_traffic - FortiGate firewall traffic logs
-- 2. network_logs.threat_logs - Threat/security event logs
-- 3. network_logs.pa_traffic - Palo Alto firewall traffic logs

describe network_logs.threat_logs
describe network_logs.pa_traffic
network_logs.pa_urls
USE network_logs


SELECT * FROM fortigate_traffic ORDER BY timestamp DESC LIMIT 10;
SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT 10;
SELECT * FROM pa_traffic ORDER BY timestamp DESC LIMIT 10;

-- Palo Alto Traffic Logs Table (pa_traffic)
CREATE TABLE network_logs.pa_traffic
(
    -- Timestamp and metadata
    timestamp DateTime,
    raw_message String,
    
    -- Device information
    device_name String,
    serial String,
    
    -- Log type information
    log_type String,
    log_subtype String,
    
    -- Time information
    generated_time DateTime,
    received_time DateTime,
    
    -- Session information
    session_id UInt64,
    repeat_count UInt32,
    
    -- Source information
    src_ip IPv4,
    src_port UInt16,
    src_zone String,
    src_interface String,
    src_user String,
    src_mac String,
    
    -- Destination information
    dst_ip IPv4,
    dst_port UInt16,
    dst_zone String,
    dst_interface String,
    dst_user String,
    dst_mac String,
    
    -- NAT information
    nat_src_ip IPv4,
    nat_src_port UInt16,
    nat_dst_ip IPv4,
    nat_dst_port UInt16,
    
    -- Rule/Policy information
    rule_name String,
    rule_uuid String,
    
    -- Application information
    application String,
    app_category String,
    app_subcategory String,
    app_technology String,
    app_risk UInt8,
    
    -- Protocol and service
    protocol UInt8,
    ip_protocol String,
    
    -- Action and result
    action String,
    
    -- Traffic statistics
    bytes_sent UInt64,
    bytes_received UInt64,
    packets_sent UInt64,
    packets_received UInt64,
    
    -- Session details
    session_start_time DateTime,
    elapsed_time UInt32,
    
    -- Location information
    src_country String,
    dst_country String,
    src_location String,
    dst_location String,
    
    -- URL and content
    url_category String,
    url_filename String,
    
    -- Security information
    threat_id String,
    threat_category String,
    severity String,
    direction String,
    
    -- Device group hierarchy
    device_group_hierarchy1 String,
    device_group_hierarchy2 String,
    device_group_hierarchy3 String,
    device_group_hierarchy4 String,
    
    -- Virtual system
    vsys String,
    vsys_name String,
    
    -- Additional fields
    sequence_number UInt64,
    action_flags String,
    tunnel_type String,
    tunnel_id UInt32,
    parent_session_id UInt64,
    parent_start_time DateTime,
    
    -- Indexes for performance
    log_date Date DEFAULT toDate(timestamp),
    log_hour DateTime DEFAULT toStartOfHour(timestamp)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE threat_logs
(
    -- Time fields
    `timestamp` DateTime,
    `receive_time` DateTime,
    `generated_time` DateTime,
    `start_time` DateTime,
    `parent_start_time` DateTime,
    `high_resolution_timestamp` DateTime64(6),
    
    -- Device identification
    `serial_number` String,
    `device_name` String,
    `host_id` String,
    
    -- Log metadata
    `type` String,
    `threat_content_type` String,
    `log_action` String,
    `action` String,
    `action_source` String,
    `action_flags` String,
    `sequence_number` UInt64,
    `session_id` UInt64,
    `parent_session_id` UInt64,
    `repeat_count` UInt32,
    `policy_id` UInt32,
    `rule_uuid` String,
    
    -- Network information (Supporting both IPv4 and IPv6)
    `source_address` String,  -- Can store both IPv4 and IPv6
    `destination_address` String,  -- Can store both IPv4 and IPv6
    `nat_source_ip` String,  -- Can store both IPv4 and IPv6
    `nat_destination_ip` String,  -- Can store both IPv4 and IPv6
    `source_port` UInt16,
    `destination_port` UInt16,
    `nat_source_port` UInt16,
    `nat_destination_port` UInt16,
    `protocol` UInt8,
    
    -- User and application
    `source_user` String,
    `destination_user` String,
    `application` String,
    `tunneled_application` String,
    `application_subcategory` String,
    `application_category` String,
    `application_technology` String,
    `application_risk` String,
    `application_characteristic` String,
    `application_container` String,
    `application_saas` String,
    `application_sanctioned_state` String,
    `app_flap_count` UInt32,
    
    -- Zone and interface
    `source_zone` String,
    `destination_zone` String,
    `inbound_interface` String,
    `outbound_interface` String,
    
    -- Location
    `source_country` String,
    `destination_country` String,
    
    -- Virtual system
    `virtual_system` String,
    `virtual_system_name` String,
    
    -- Rule information
    `rule_name` String,
    
    -- Traffic metrics
    `bytes` UInt64,
    `bytes_sent` UInt64,
    `bytes_received` UInt64,
    `packets` UInt64,
    `packets_sent` UInt64,
    `packets_received` UInt64,
    `elapsed_time` UInt32,
    
    -- Session details
    `flags` String,
    `session_end_reason` String,
    `category` String,
    
    -- Device hierarchy
    `device_group_hierarchy_level_1` String,
    `device_group_hierarchy_level_2` String,
    `device_group_hierarchy_level_3` String,
    `device_group_hierarchy_level_4` String,
    
    -- VM information
    `source_vm_uuid` String,
    `destination_vm_uuid` String,
    
    -- Tunnel information
    `tunnel_id_imsi` String,
    `monitor_tag_imei` String,
    `tunnel_type` String,
    
    -- SCTP information
    `sctp_association_id` String,
    `sctp_chunks` UInt32,
    `sctp_chunks_sent` UInt32,
    `sctp_chunks_received` UInt32,
    
    -- HTTP/2
    `http2_connection` String,
    
    -- SD-WAN
    `link_switches` UInt32,
    `sdwan_cluster` String,
    `sdwan_device_type` String,
    `sdwan_cluster_type` String,
    `sdwan_site` String,
    
    -- Dynamic groups and lists
    `dynamic_user_group_name` String,
    `source_external_dynamic_list` String,
    `destination_external_dynamic_list` String,
    `source_dynamic_address_group` String,
    `destination_dynamic_address_group` String,
    
    -- XFF
    `xff_address` String,  -- Can also be IPv6
    
    -- Device information
    `source_device_category` String,
    `source_device_profile` String,
    `source_device_model` String,
    `source_device_vendor` String,
    `source_device_os_family` String,
    `source_device_os_version` String,
    `source_hostname` String,
    `source_mac_address` String,
    `destination_device_category` String,
    `destination_device_profile` String,
    `destination_device_model` String,
    `destination_device_vendor` String,
    `destination_device_os_family` String,
    `destination_device_os_version` String,
    `destination_hostname` String,
    `destination_mac_address` String,
    
    -- Container information
    `container_id` String,
    `pod_namespace` String,
    `pod_name` String,
    
    -- Session owner
    `session_owner` String,
    
    -- Slice information
    `a_slice_service_type` String,
    `a_slice_differentiator` String,
    
    -- Offloaded flag
    `offloaded` String,
    
    -- Raw message (optional, for debugging)
    `raw_message` String,
    
    -- Computed fields
    `log_date` Date DEFAULT toDate(timestamp),
    `log_time` String DEFAULT formatDateTime(timestamp, '%H:%M:%S')
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_address, destination_address, threat_content_type)
TTL timestamp + INTERVAL 90 DAY;