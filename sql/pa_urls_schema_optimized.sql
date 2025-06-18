-- Optimized PaloAlto URL Filtering Logs Table Schema
-- Essential fields for comprehensive URL filtering analysis

DROP TABLE IF EXISTS network_logs.pa_urls_optimized;

CREATE TABLE network_logs.pa_urls_optimized
(
    -- Core Identification & Timestamps
    timestamp           DateTime DEFAULT now(),
    receive_time        DateTime DEFAULT now(),
    generated_time      DateTime DEFAULT now(),
    processing_timestamp DateTime DEFAULT now(),
    sequence_number     UInt64   DEFAULT 0,
    session_id          UInt64   DEFAULT 0,
    device_name         String   DEFAULT '',
    serial_number       String   DEFAULT '',
    
    -- Network & Connection Information
    source_address      String   DEFAULT '',
    destination_address String   DEFAULT '',
    nat_source_ip       String   DEFAULT '',
    nat_destination_ip  String   DEFAULT '',
    source_port         UInt16   DEFAULT 0,
    destination_port    UInt16   DEFAULT 0,
    source_zone         String   DEFAULT '',
    destination_zone    String   DEFAULT '',
    inbound_interface   String   DEFAULT '',
    outbound_interface  String   DEFAULT '',
    ip_protocol         UInt8    DEFAULT 0,
    protocol            String   DEFAULT '',
    
    -- URL & Web Analysis
    url                 String   DEFAULT '',
    url_domain          String   DEFAULT '',
    url_path            String   DEFAULT '',
    url_query           String   DEFAULT '',
    url_category        String   DEFAULT '',
    url_category_list   String   DEFAULT '',
    http_method         String   DEFAULT '',
    user_agent          String   DEFAULT '',
    referer             String   DEFAULT '',
    content_type        String   DEFAULT '',
    response_code       UInt16   DEFAULT 0,
    response_size       UInt64   DEFAULT 0,
    
    -- Security & Policy
    rule_name           String   DEFAULT '',
    rule_uuid           String   DEFAULT '',
    action              String   DEFAULT '',
    severity            String   DEFAULT '',
    direction           String   DEFAULT '',
    threat_id           String   DEFAULT '',
    threat_category     String   DEFAULT '',
    log_action          String   DEFAULT '',
    
    -- User & Application
    source_user         String   DEFAULT '',
    destination_user    String   DEFAULT '',
    application         String   DEFAULT '',
    application_category String   DEFAULT '',
    source_country      String   DEFAULT '',
    destination_country String   DEFAULT '',
    
    -- System & Raw Data
    raw_message         String   DEFAULT '',
    log_type            String   DEFAULT '',
    log_subtype         String   DEFAULT '',
    virtual_system      String   DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, device_name, url_domain, action)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Create indexes for common queries
CREATE INDEX idx_url_domain ON network_logs.pa_urls_optimized (url_domain) TYPE bloom_filter GRANULARITY 1;
CREATE INDEX idx_url_category ON network_logs.pa_urls_optimized (url_category) TYPE bloom_filter GRANULARITY 1;
CREATE INDEX idx_action ON network_logs.pa_urls_optimized (action) TYPE bloom_filter GRANULARITY 1;
CREATE INDEX idx_source_user ON network_logs.pa_urls_optimized (source_user) TYPE bloom_filter GRANULARITY 1;
CREATE INDEX idx_application ON network_logs.pa_urls_optimized (application) TYPE bloom_filter GRANULARITY 1;