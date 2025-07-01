use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{debug, warn};

// URL log fields based on the documentation format
const URL_LOG_FIELDS: &[&str] = &[
    "FUTURE_USE",           // 0
    "receive_time",         // 1
    "serial_number",        // 2
    "type",                 // 3
    "threat_content_type",  // 4
    "FUTURE_USE2",          // 5
    "generated_time",       // 6
    "source_address",       // 7
    "destination_address",  // 8
    "nat_source_ip",        // 9
    "nat_destination_ip",   // 10
    "rule_name",            // 11
    "source_user",          // 12
    "destination_user",     // 13
    "application",          // 14
    "virtual_system",       // 15
    "source_zone",          // 16
    "destination_zone",     // 17
    "inbound_interface",    // 18
    "outbound_interface",   // 19
    "log_action",           // 20
    "FUTURE_USE3",          // 21
    "session_id",           // 22
    "repeat_count",         // 23
    "source_port",          // 24
    "destination_port",     // 25
    "nat_source_port",      // 26
    "nat_destination_port", // 27
    "flags",                // 28
    "ip_protocol",          // 29
    "action",               // 30
    "url_filename",         // 31
    "threat_id",            // 32
    "category",             // 33
    "severity",             // 34
    "direction",            // 35
    "sequence_number",      // 36
    "action_flags",         // 37
    "source_country",       // 38
    "destination_country",  // 39
    "FUTURE_USE4",          // 40
    "content_type",         // 41
    "pcap_id",              // 42
    "file_digest",          // 43
    "cloud",                // 44
    "url_index",            // 45
    "user_agent",           // 46
    "file_type",            // 47
    "x_forwarded_for",      // 48
    "referer",              // 49
    "sender",               // 50
    "subject",              // 51
    "recipient",            // 52
    "report_id",            // 53
    "device_group_hierarchy1", // 54
    "device_group_hierarchy2", // 55
    "device_group_hierarchy3", // 56
    "device_group_hierarchy4", // 57
    "virtual_system_name",  // 58
    "device_name",          // 59
    "FUTURE_USE5",          // 60
    "source_vm_uuid",       // 61
    "destination_vm_uuid",  // 62
    "http_method",          // 63
    "tunnel_id_imsi",       // 64
    "monitor_tag_imei",     // 65
    "parent_session_id",    // 66
    "parent_start_time",    // 67
    "tunnel_type",          // 68
    "threat_category",      // 69
    "content_version",      // 70
    "FUTURE_USE6",          // 71
    "sctp_association_id",  // 72
    "payload_protocol_id",  // 73
    "http_headers",         // 74
    "url_category_list",    // 75
    "rule_uuid",            // 76
    "http2_connection",     // 77
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaloAltoUrlRecord {
    pub timestamp: DateTime<Utc>,
    pub receive_time: DateTime<Utc>,
    pub generated_time: DateTime<Utc>,
    pub processing_timestamp: DateTime<Utc>,
    pub sequence_number: u64,
    pub session_id: u64,
    pub device_name: String,
    pub serial_number: String,
    pub source_address: String,
    pub destination_address: String,
    pub nat_source_ip: String,
    pub nat_destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub source_zone: String,
    pub destination_zone: String,
    pub inbound_interface: String,
    pub outbound_interface: String,
    pub ip_protocol: u8,
    pub protocol: String,
    pub url: String,
    pub url_domain: String,
    pub url_path: String,
    pub url_query: String,
    pub url_category: String,
    pub url_category_list: String,
    pub http_method: String,
    pub user_agent: String,
    pub referer: String,
    pub content_type: String,
    pub response_code: u16,
    pub response_size: u64,
    pub rule_name: String,
    pub rule_uuid: String,
    pub action: String,
    pub severity: String,
    pub direction: String,
    pub threat_id: String,
    pub threat_category: String,
    pub log_action: String,
    pub source_user: String,
    pub destination_user: String,
    pub application: String,
    pub application_category: String,
    pub source_country: String,
    pub destination_country: String,
    pub raw_message: String,
    pub log_type: String,
    pub log_subtype: String,
    pub virtual_system: String,
    // Device info (set by device manager)
    pub device_ip: String,
}

impl Default for PaloAltoUrlRecord {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            receive_time: Utc::now(),
            generated_time: Utc::now(),
            processing_timestamp: Utc::now(),
            sequence_number: 0,
            session_id: 0,
            device_name: String::new(),
            serial_number: String::new(),
            source_address: String::new(),
            destination_address: String::new(),
            nat_source_ip: String::new(),
            nat_destination_ip: String::new(),
            source_port: 0,
            destination_port: 0,
            source_zone: String::new(),
            destination_zone: String::new(),
            inbound_interface: String::new(),
            outbound_interface: String::new(),
            ip_protocol: 0,
            protocol: String::new(),
            url: String::new(),
            url_domain: String::new(),
            url_path: String::new(),
            url_query: String::new(),
            url_category: String::new(),
            url_category_list: String::new(),
            http_method: String::new(),
            user_agent: String::new(),
            referer: String::new(),
            content_type: String::new(),
            response_code: 0,
            response_size: 0,
            rule_name: String::new(),
            rule_uuid: String::new(),
            action: String::new(),
            severity: String::new(),
            direction: String::new(),
            threat_id: String::new(),
            threat_category: String::new(),
            log_action: String::new(),
            source_user: String::new(),
            destination_user: String::new(),
            application: String::new(),
            application_category: String::new(),
            source_country: String::new(),
            destination_country: String::new(),
            raw_message: String::new(),
            log_type: "THREAT".to_string(),
            log_subtype: "url".to_string(),
            virtual_system: String::new(),
            device_ip: String::new(),
        }
    }
}

impl PaloAltoUrlRecord {
    pub fn parse(line: &str) -> Result<Self> {
        let mut record = PaloAltoUrlRecord::default();
        record.raw_message = line.trim().to_string();
        record.processing_timestamp = Utc::now();
        
        // Strip syslog header if present
        let csv_part = if let Some(start_pos) = line.find("1,202") {
            &line[start_pos..]
        } else {
            line
        };
        
        // Parse CSV fields
        let fields: Vec<String> = parse_csv_fields(csv_part);
        
        debug!("Parsed {} fields from Palo Alto URL log line", fields.len());
        
        if fields.len() < 76 {
            warn!("Palo Alto URL log has insufficient fields: {} (expected at least 76)", fields.len());
            return Err(anyhow::anyhow!("Insufficient fields in Palo Alto URL log"));
        }
        
        // Verify this is a THREAT,url log
        let log_type = fields.get(3).map(|s| s.as_str()).unwrap_or("");
        let threat_type = fields.get(4).map(|s| s.as_str()).unwrap_or("");
        
        if log_type != "THREAT" || threat_type != "url" {
            return Err(anyhow::anyhow!("Not a THREAT,url log: {},{}", log_type, threat_type));
        }
        
        // Parse timestamps
        record.receive_time = parse_palo_alto_timestamp(fields.get(1).map(|s| s.as_str()).unwrap_or(""))
            .unwrap_or_else(Utc::now);
        record.generated_time = parse_palo_alto_timestamp(fields.get(6).map(|s| s.as_str()).unwrap_or(""))
            .unwrap_or_else(Utc::now);
        record.timestamp = record.generated_time;
        
        // Basic fields
        record.serial_number = fields.get(2).map(|s| s.to_string()).unwrap_or_default();
        record.log_type = log_type.to_string();
        record.log_subtype = threat_type.to_string();
        
        // Network information
        record.source_address = fields.get(7).map(|s| s.to_string()).unwrap_or_default();
        record.destination_address = fields.get(8).map(|s| s.to_string()).unwrap_or_default();
        record.nat_source_ip = fields.get(9).map(|s| s.to_string()).unwrap_or_default();
        record.nat_destination_ip = fields.get(10).map(|s| s.to_string()).unwrap_or_default();
        record.source_port = fields.get(24).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
        record.destination_port = fields.get(25).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
        
        // Zones and interfaces
        record.source_zone = fields.get(16).map(|s| s.to_string()).unwrap_or_default();
        record.destination_zone = fields.get(17).map(|s| s.to_string()).unwrap_or_default();
        record.inbound_interface = fields.get(18).map(|s| s.to_string()).unwrap_or_default();
        record.outbound_interface = fields.get(19).map(|s| s.to_string()).unwrap_or_default();
        
        // User information
        record.source_user = fields.get(12).map(|s| s.to_string()).unwrap_or_default();
        record.destination_user = fields.get(13).map(|s| s.to_string()).unwrap_or_default();
        
        // Application and system
        record.application = fields.get(14).map(|s| s.to_string()).unwrap_or_default();
        record.virtual_system = fields.get(15).map(|s| s.to_string()).unwrap_or_default();
        
        // Protocol information
        record.protocol = fields.get(29).map(|s| s.to_string()).unwrap_or_default();
        record.ip_protocol = map_protocol(fields.get(29).map(|s| s.as_str()).unwrap_or(""));
        
        // Action and log details
        record.action = fields.get(30).map(|s| s.to_string()).unwrap_or_default();
        record.log_action = fields.get(20).map(|s| s.to_string()).unwrap_or_default();
        
        // URL and threat information
        record.url = fields.get(31).map(|s| s.to_string()).unwrap_or_default();
        record.threat_id = fields.get(32).map(|s| s.to_string()).unwrap_or_default();
        record.url_category = fields.get(33).map(|s| s.to_string()).unwrap_or_default();
        record.severity = fields.get(34).map(|s| s.to_string()).unwrap_or_default();
        record.direction = fields.get(35).map(|s| s.to_string()).unwrap_or_default();
        
        // Session information
        record.session_id = fields.get(22).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        record.sequence_number = fields.get(36).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        
        // Geographic information
        record.source_country = fields.get(38).map(|s| s.to_string()).unwrap_or_default();
        record.destination_country = fields.get(39).map(|s| s.to_string()).unwrap_or_default();
        
        // Rule information
        record.rule_name = fields.get(11).map(|s| s.to_string()).unwrap_or_default();
        
        // HTTP specific fields (if available)
        if fields.len() > 46 {
            record.user_agent = fields.get(46).map(|s| s.to_string()).unwrap_or_default();
        }
        if fields.len() > 49 {
            record.referer = fields.get(49).map(|s| s.to_string()).unwrap_or_default();
        }
        if fields.len() > 63 {
            record.http_method = fields.get(63).map(|s| s.to_string()).unwrap_or_default();
        }
        if fields.len() > 69 {
            record.threat_category = fields.get(69).map(|s| s.to_string()).unwrap_or_default();
        }
        if fields.len() > 75 {
            record.url_category_list = fields.get(75).map(|s| s.to_string()).unwrap_or_default();
        }
        if fields.len() > 76 {
            record.rule_uuid = fields.get(76).map(|s| s.to_string()).unwrap_or_default();
        }
        
        // Parse URL to extract domain, path, and query
        record.parse_url_components();
        
        // Device name from field 59
        if fields.len() > 59 {
            record.device_name = fields.get(59).map(|s| s.to_string()).unwrap_or_default();
        }
        
        Ok(record)
    }
    
    fn parse_url_components(&mut self) {
        if self.url.is_empty() {
            return;
        }
        
        let mut url_str = self.url.as_str();
        // Remove potential protocol prefixes for domain extraction
        if let Some(stripped) = url_str.strip_prefix("https://") {
            url_str = stripped;
        } else if let Some(stripped) = url_str.strip_prefix("http://") {
            url_str = stripped;
        }

        let mut parts = url_str.splitn(2, '/');
        self.url_domain = parts.next().unwrap_or("").to_string();
        if let Some(path_and_query) = parts.next() {
            let mut path_parts = path_and_query.splitn(2, '?');
            self.url_path = format!("/{}", path_parts.next().unwrap_or(""));
            self.url_query = path_parts.next().unwrap_or("").to_string();
        } else {
            self.url_path = "/".to_string();
        }
    }
    
    pub fn validate(&self) -> bool {
        // Must have basic info
        let has_basic_info = !self.raw_message.is_empty() && 
                            !self.device_name.is_empty() &&
                            self.log_type == "THREAT" &&
                            self.log_subtype == "url";
        
        // Must have valid IPs
        let has_valid_ips = !self.source_address.is_empty() && 
                           !self.destination_address.is_empty();
        
        // Must have URL
        let has_url = !self.url.is_empty();
        
        has_basic_info && has_valid_ips && has_url
    }
    
    pub fn set_device_info(&mut self, device_name: &str, device_ip: &str) {
        if self.device_name.is_empty() {
            self.device_name = device_name.to_string();
        }
        self.device_ip = device_ip.to_string();
    }
}

fn parse_palo_alto_timestamp(timestamp_str: &str) -> Option<DateTime<Utc>> {
    // Palo Alto timestamp format: YYYY/MM/DD HH:MM:SS
    match NaiveDateTime::parse_from_str(timestamp_str, "%Y/%m/%d %H:%M:%S") {
        Ok(naive_dt) => Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc)),
        Err(e) => {
            warn!("Failed to parse Palo Alto timestamp '{}': {}", timestamp_str, e);
            None
        }
    }
}

fn parse_csv_fields(csv_line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;
    let mut chars = csv_line.chars().peekable();
    
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    if chars.peek() == Some(&'"') {
                        current_field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(current_field.trim().to_string());
                current_field.clear();
            }
            _ => {
                current_field.push(ch);
            }
        }
    }
    
    fields.push(current_field.trim().to_string());
    fields
}

fn map_protocol(protocol: &str) -> u8 {
    match protocol.to_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "igmp" => 2,
        "esp" => 50,
        "ah" => 51,
        "gre" => 47,
        "ipv6-icmp" => 58,
        _ => protocol.parse::<u8>().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_palo_alto_url_log() {
        let log_line = r#"Jul  1 14:14:38 SMO-RUH-MU04-F09R14-INT-FW01.smo.sa 1,2025/07/01 14:14:37,024301003410,THREAT,url,2817,2025/07/01 14:14:37,10.10.200.210,54.68.97.123,185.27.220.65,54.68.97.123,Close Social Media_WEB_Brwosing,smo\h.alotaibi,,ssl,vsys1,HQ_INT_CORE,OutSide_Mobily,ae1.2004,ethernet1/7,SMOEDL,2025/07/01 14:14:37,712946,1,51493,443,33796,443,0x42b400,tcp,alert,"osce140-en.fbs25.trendmicro.com/",(9999),computer-and-internet-info,informational,client-to-server,7508761568363193331,0x0,10.0.0.0-10.255.255.255,United States,,,0,,,0,,,,,,,,0,210,14,0,0,,SMO-RUH-MU04-F09R14-INT-FW01,,,,,0,,0,,N/A,N/A,AppThreat-0-0,0x0,0,4294967295,,"computer-and-internet-info,low-risk",7ef917ba-fdb6-45d3-b3b4-8df792316988,0"#;
        
        let record = PaloAltoUrlRecord::parse(log_line).unwrap();
        
        assert_eq!(record.log_type, "THREAT");
        assert_eq!(record.log_subtype, "url");
        assert_eq!(record.source_address, "10.10.200.210");
        assert_eq!(record.destination_address, "54.68.97.123");
        assert_eq!(record.url, "osce140-en.fbs25.trendmicro.com/");
        assert_eq!(record.url_domain, "osce140-en.fbs25.trendmicro.com");
        assert_eq!(record.url_path, "/");
        assert_eq!(record.action, "alert");
        assert_eq!(record.url_category, "computer-and-internet-info");
        assert_eq!(record.severity, "informational");
    }
}