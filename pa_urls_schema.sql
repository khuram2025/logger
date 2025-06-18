-- PaloAlto Networks URL Filtering Logs Table
-- Optimized ClickHouse schema for network_logs.pa_urls
-- Based on PAN-OS 11.0 URL filtering log format

USE network_logs;

CREATE TABLE IF NOT EXISTS network_logs.pa_urls
(
    -- ==== Timestamp and Metadata Fields ====
    timestamp DateTime,
    receive_time DateTime,
    generated_time DateTime,
    start_time DateTime,
    high_resolution_timestamp DateTime64(6),
    
    -- ==== Device and System Identification ====
    serial_number String,
    device_name String,
    host_id String,
    virtual_system String,
    virtual_system_name String,
    
    -- ==== Log Metadata ====
    log_type String,
    log_subtype String,
    config_version String,
    sequence_number UInt64,
    
    -- ==== Session Information ====
    session_id UInt64,
    repeat_count UInt32,
    session_end_reason String,
    start_time_utc DateTime,
    elapsed_time UInt32,
    
    -- ==== Network Connection Information ====
    source_address String,  -- IPv4/IPv6 compatible
    destination_address String,  -- IPv4/IPv6 compatible
    nat_source_ip String,
    nat_destination_ip String,
    source_port UInt16,
    destination_port UInt16,
    nat_source_port UInt16,
    nat_destination_port UInt16,
    ip_protocol UInt8,
    protocol String,
    
    -- ==== Zone and Interface Information ====
    source_zone String,
    destination_zone String,
    inbound_interface String,
    outbound_interface String,
    
    -- ==== User and Authentication ====
    source_user String,
    destination_user String,
    source_user_domain String,
    destination_user_domain String,
    
    -- ==== URL and Web-Specific Fields ====
    url String,  -- Complete URL
    url_domain String,  -- Domain portion
    url_path String,  -- Path portion
    url_query String,  -- Query parameters
    url_fragment String,  -- Fragment identifier
    url_category_list String,  -- Comma-separated categories
    url_category String,  -- Primary category
    url_index UInt32,
    
    -- ==== HTTP/HTTPS Specific Fields ====
    http_method String,  -- GET, POST, PUT, etc.
    http_version String,  -- HTTP/1.1, HTTP/2, etc.
    user_agent String,
    referer String,
    content_type String,
    content_length UInt64,
    response_code UInt16,
    response_size UInt64,
    request_size UInt64,
    
    -- ==== SSL/TLS Information ====
    ssl_version String,
    ssl_cipher String,
    ssl_certificate_subject String,
    ssl_certificate_issuer String,
    ssl_certificate_serial String,
    ssl_certificate_fingerprint String,
    
    -- ==== Security and Policy ====
    rule_name String,
    rule_uuid String,
    policy_id UInt32,
    policy_name String,
    url_filtering_profile String,
    action String,  -- allow, block, alert, override
    action_source String,
    log_action String,
    
    -- ==== Application Information ====
    application String,
    application_category String,
    application_subcategory String,
    application_technology String,
    application_risk UInt8,
    application_characteristic String,
    tunneled_application String,
    
    -- ==== Geographic Information ====
    source_country String,
    destination_country String,
    source_location String,
    destination_location String,
    
    -- ==== Device Identification ====
    source_device_category String,
    source_device_profile String,
    source_device_model String,
    source_device_vendor String,
    source_device_os_family String,
    source_device_os_version String,
    source_hostname String,
    source_mac_address String,
    
    destination_device_category String,
    destination_device_profile String,
    destination_device_model String,
    destination_device_vendor String,
    destination_device_os_family String,
    destination_device_os_version String,
    destination_hostname String,
    destination_mac_address String,
    
    -- ==== Traffic Metrics ====
    bytes_sent UInt64,
    bytes_received UInt64,
    packets_sent UInt64,
    packets_received UInt64,
    total_bytes UInt64,
    total_packets UInt64,
    
    -- ==== Security Threat Information ====
    threat_id String,
    threat_category String,
    severity String,
    direction String,
    file_digest String,
    file_type String,
    wildfire_verdict String,
    
    -- ==== Advanced Features ====
    xff_address String,  -- X-Forwarded-For
    dynamic_user_group_name String,
    source_external_dynamic_list String,
    destination_external_dynamic_list String,
    source_dynamic_address_group String,
    destination_dynamic_address_group String,
    
    -- ==== Hierarchy and Organization ====
    device_group_hierarchy_level_1 String,
    device_group_hierarchy_level_2 String,
    device_group_hierarchy_level_3 String,
    device_group_hierarchy_level_4 String,
    
    -- ==== Container and Cloud Information ====
    container_id String,
    pod_namespace String,
    pod_name String,
    cloud_instance_id String,
    cloud_provider String,
    cloud_region String,
    
    -- ==== QoS and Performance ====
    qos_class String,
    qos_rule String,
    response_time_ms UInt32,
    dns_resolution_time_ms UInt16,
    tcp_handshake_time_ms UInt16,
    ssl_handshake_time_ms UInt16,
    
    -- ==== URL Override and Audit ====
    override_user String,
    override_reason String,
    override_timestamp DateTime,
    audit_comment String,
    
    -- ==== Machine Learning and Analytics ====
    risk_score Float32,
    anomaly_score Float32,
    reputation_score Float32,
    
    -- ==== Compliance and Legal ====
    data_classification String,
    compliance_tag String,
    legal_hold_flag UInt8,
    
    -- ==== Custom and Future Fields ====
    custom_field_1 String,
    custom_field_2 String,
    custom_field_3 String,
    tags Array(String),
    
    -- ==== System Fields ====
    raw_message String,
    processing_timestamp DateTime DEFAULT now(),
    log_date Date DEFAULT toDate(timestamp),
    log_hour DateTime DEFAULT toStartOfHour(timestamp)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
PRIMARY KEY (timestamp, source_address, destination_address, url_domain, action)
ORDER BY (timestamp, source_address, destination_address, url_domain, action, session_id)
TTL timestamp + INTERVAL 90 DAY
SETTINGS 
    index_granularity = 8192,
    merge_tree_max_rows_to_use_cache = 16777216,
    merge_tree_max_bytes_to_use_cache = 2013265920;

-- ==== Indexes for Performance Optimization ====

-- Bloom filter indexes for fast domain and user lookups
ALTER TABLE network_logs.pa_urls ADD INDEX idx_url_domain_bloom url_domain TYPE bloom_filter GRANULARITY 1;
ALTER TABLE network_logs.pa_urls ADD INDEX idx_source_user_bloom source_user TYPE bloom_filter GRANULARITY 1;
ALTER TABLE network_logs.pa_urls ADD INDEX idx_destination_user_bloom destination_user TYPE bloom_filter GRANULARITY 1;
ALTER TABLE network_logs.pa_urls ADD INDEX idx_user_agent_bloom user_agent TYPE bloom_filter GRANULARITY 1;

-- Set indexes for categorical data
ALTER TABLE network_logs.pa_urls ADD INDEX idx_url_category_set url_category TYPE set(1000) GRANULARITY 1;
ALTER TABLE network_logs.pa_urls ADD INDEX idx_application_set application TYPE set(1000) GRANULARITY 1;
ALTER TABLE network_logs.pa_urls ADD INDEX idx_action_set action TYPE set(100) GRANULARITY 1;
ALTER TABLE network_logs.pa_urls ADD INDEX idx_http_method_set http_method TYPE set(50) GRANULARITY 1;

-- MinMax indexes for numeric ranges
ALTER TABLE network_logs.pa_urls ADD INDEX idx_response_code_minmax response_code TYPE minmax GRANULARITY 8;
ALTER TABLE network_logs.pa_urls ADD INDEX idx_response_time_minmax response_time_ms TYPE minmax GRANULARITY 8;
ALTER TABLE network_logs.pa_urls ADD INDEX idx_content_length_minmax content_length TYPE minmax GRANULARITY 8;

-- ==== Sample Queries for Testing ====

-- Test basic functionality
-- INSERT INTO network_logs.pa_urls 
-- (timestamp, device_name, source_address, destination_address, url, url_domain, url_category, action, http_method, response_code, user_agent, source_user)
-- VALUES 
-- (now(), 'PA-FW01', '192.168.1.100', '8.8.8.8', 'https://www.google.com/search?q=test', 'www.google.com', 'search-engines', 'allow', 'GET', 200, 'Mozilla/5.0', 'john.doe');

-- Test query performance
-- SELECT 
--     toDate(timestamp) as date,
--     url_category,
--     action,
--     count() as requests,
--     countIf(action = 'block') as blocked,
--     uniq(source_address) as unique_users,
--     uniq(url_domain) as unique_domains
-- FROM network_logs.pa_urls 
-- WHERE timestamp >= now() - INTERVAL 1 DAY
-- GROUP BY date, url_category, action
-- ORDER BY requests DESC;

-- ==== Materialized Views for Analytics ====

-- Hourly URL category summary
CREATE MATERIALIZED VIEW IF NOT EXISTS network_logs.pa_urls_hourly_summary
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, url_category, action, device_name)
AS SELECT
    toStartOfHour(timestamp) as hour,
    url_category,
    action,
    device_name,
    count() as requests,
    countIf(action = 'block') as blocked_requests,
    countIf(action = 'allow') as allowed_requests,
    uniq(source_address) as unique_users,
    uniq(url_domain) as unique_domains,
    sum(bytes_sent) as total_bytes_sent,
    sum(bytes_received) as total_bytes_received,
    avg(response_time_ms) as avg_response_time
FROM network_logs.pa_urls
GROUP BY hour, url_category, action, device_name;

-- Daily user activity tracking
CREATE MATERIALIZED VIEW IF NOT EXISTS network_logs.pa_urls_user_daily
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, source_user, device_name)
AS SELECT
    toDate(timestamp) as date,
    source_user,
    device_name,
    count() as total_requests,
    countIf(action = 'block') as blocked_requests,
    uniq(url_domain) as unique_domains,
    uniq(url_category) as unique_categories,
    sum(bytes_sent + bytes_received) as total_bytes,
    min(timestamp) as first_activity,
    max(timestamp) as last_activity
FROM network_logs.pa_urls
WHERE source_user != ''
GROUP BY date, source_user, device_name;

-- Top blocked domains tracking
CREATE MATERIALIZED VIEW IF NOT EXISTS network_logs.pa_urls_blocked_domains
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, url_domain, url_category)
AS SELECT
    toStartOfHour(timestamp) as hour,
    url_domain,
    url_category,
    count() as blocked_count,
    uniq(source_address) as unique_users_blocked,
    uniq(source_user) as unique_usernames_blocked
FROM network_logs.pa_urls
WHERE action IN ('block', 'deny', 'drop')
GROUP BY hour, url_domain, url_category;