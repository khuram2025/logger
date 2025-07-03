use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use lazy_static::lazy_static;
use tracing::{debug, warn};

lazy_static! {
    static ref CSV_REGEX: Regex = Regex::new(r",").unwrap();
}

// Palo Alto traffic log fields mapping based on PAN-OS 10.2 documentation
const TRAFFIC_LOG_FIELDS: &[&str] = &[
    "FUTURE_USE",           // 0
    "receive_time",         // 1
    "serial_number",        // 2
    "type",                 // 3
    "threat_content_type",  // 4
    "FUTURE_USE2",          // 5
    "generated_time",       // 6
    "src_ip",               // 7
    "dst_ip",               // 8
    "nat_src_ip",           // 9
    "nat_dst_ip",           // 10
    "rule_name",            // 11
    "src_user",             // 12
    "dst_user",             // 13
    "application",          // 14
    "virtual_system",       // 15
    "src_zone",             // 16
    "dst_zone",             // 17
    "inbound_interface",    // 18
    "outbound_interface",   // 19
    "log_action",           // 20
    "FUTURE_USE3",          // 21
    "session_id",           // 22
    "repeat_count",         // 23
    "src_port",             // 24
    "dst_port",             // 25
    "nat_src_port",         // 26
    "nat_dst_port",         // 27
    "flags",                // 28
    "protocol",             // 29
    "action",               // 30
    "bytes_total",          // 31
    "bytes_sent",           // 32
    "bytes_received",       // 33
    "packets_total",        // 34
    "start_time",           // 35
    "elapsed_time",         // 36
    "category",             // 37
    "FUTURE_USE4",          // 38
    "sequence_number",      // 39
    "action_flags",         // 40
    "src_location",         // 41
    "dst_location",         // 42
    "FUTURE_USE5",          // 43
    "packets_sent",         // 44
    "packets_received",     // 45
    "session_end_reason",   // 46
    "device_group_hierarchy1", // 47
    "device_group_hierarchy2", // 48
    "device_group_hierarchy3", // 49
    "device_group_hierarchy4", // 50
    "vsys_name",            // 51
    "device_name",          // 52
    "action_source",        // 53
    "src_uuid",             // 54
    "dst_uuid",             // 55
    "tunnel_id",            // 56
    "monitor_tag",          // 57
    "parent_session_id",    // 58
    "parent_start_time",    // 59
    "tunnel_type",          // 60
    "sctp_association_id",  // 61
    "sctp_chunks",          // 62
    "sctp_chunks_sent",     // 63
    "sctp_chunks_received", // 64
    "rule_uuid",            // 65
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaloAltoRecord {
    pub timestamp: DateTime<Utc>,
    pub raw_message: String,
    pub devname: String,
    pub devid: String,
    pub eventtime: u64,
    pub tz: String,
    pub logid: String,
    pub log_type: String,
    pub subtype: String,
    pub level: String,
    pub vd: String,
    pub srcip: String,
    pub srcport: u32,
    pub srcintf: String,
    pub srcintfrole: String,
    pub dstip: String,
    pub dstport: u32,
    pub dstintf: String,
    pub dstintfrole: String,
    pub srccountry: String,
    pub dstcountry: String,
    pub sessionid: u64,
    pub proto: u32,
    pub action: String,
    pub policyid: u32,
    pub policytype: String,
    pub poluuid: String,
    pub policyname: String,
    pub service: String,
    pub trandisp: String,
    pub appcat: String,
    pub duration: u64,
    pub sentbyte: u64,
    pub rcvdbyte: u64,
    pub sentpkt: u64,
    pub rcvdpkt: u64,
    pub sentdelta: u64,
    pub rcvddelta: u64,
    pub durationdelta: u64,
    pub sentpktdelta: u64,
    pub rcvdpktdelta: u64,
    pub vpntype: String,
    // Device information
    pub device_name: String,
    pub device_ip: String,
}

impl Default for PaloAltoRecord {
    fn default() -> Self {
        PaloAltoRecord {
            timestamp: Utc::now(),
            raw_message: String::new(),
            devname: String::new(),
            devid: String::new(),
            eventtime: 0,
            tz: String::new(),
            logid: String::new(),
            log_type: String::new(),
            subtype: String::new(),
            level: String::new(),
            vd: String::new(),
            srcip: "0.0.0.0".to_string(),
            srcport: 0,
            srcintf: String::new(),
            srcintfrole: String::new(),
            dstip: "0.0.0.0".to_string(),
            dstport: 0,
            dstintf: String::new(),
            dstintfrole: String::new(),
            srccountry: String::new(),
            dstcountry: String::new(),
            sessionid: 0,
            proto: 0,
            action: String::new(),
            policyid: 0,
            policytype: String::new(),
            poluuid: String::new(),
            policyname: String::new(),
            service: String::new(),
            trandisp: String::new(),
            appcat: String::new(),
            duration: 0,
            sentbyte: 0,
            rcvdbyte: 0,
            sentpkt: 0,
            rcvdpkt: 0,
            sentdelta: 0,
            rcvddelta: 0,
            durationdelta: 0,
            sentpktdelta: 0,
            rcvdpktdelta: 0,
            vpntype: String::new(),
            device_name: String::new(),
            device_ip: String::new(),
        }
    }
}

impl PaloAltoRecord {
    pub fn parse(line: &str) -> Result<Self> {
        let mut record = PaloAltoRecord::default();
        record.raw_message = line.trim().to_string();
        
        // Strip syslog header if present (format: <priority>timestamp hostname )
        // Look for the start of CSV data which begins with "1," for Palo Alto logs
        let csv_part = if let Some(csv_start) = line.find("1,") {
            &line[csv_start..]
        } else if let Some(start_pos) = line.find(char::is_numeric) {
            // Fallback: Find the start of CSV data (first digit after syslog header)
            &line[start_pos..]
        } else {
            line
        };
        
        // Split CSV fields - handle quoted fields properly
        let fields: Vec<String> = parse_csv_fields(csv_part);
        
        debug!("Parsed {} fields from Palo Alto log line", fields.len());
        
        // Parse the fields according to actual Palo Alto format from sample
        if fields.len() >= 30 {
            // Actual field positions based on sample log:
            // 0: FUTURE_USE (1)
            // 1: receive_time (2025/06/30 16:20:51)
            // 2: serial_number (024301003410)
            // 3: type (TRAFFIC)
            // 4: threat_content_type (end)
            // 5: FUTURE_USE2 (2817)
            // 6: generated_time (2025/06/30 16:20:51)
            // 7: src_ip (10.10.200.106)
            // 8: dst_ip (142.250.201.1)
            // 9: nat_src_ip (185.27.220.65)
            // 10: nat_dst_ip (142.250.201.1)
            // 11: rule_name (Close Social Media_WEB_Brwosing)
            // 12: src_user (smo\a.batterjee)
            // 13: dst_user ()
            // 14: application (google-base)
            // 15: virtual_system (vsys1)
            // 16: src_zone (HQ_INT_CORE)
            // 17: dst_zone (OutSide_Mobily)
            // 18: inbound_interface (ae1.2004)
            // 19: outbound_interface (ethernet1/7)
            // 20: log_action (SMOEDL)
            // 21: FUTURE_USE3 (2025/06/30 16:20:51)
            // 22: session_id (1416318)
            // 23: repeat_count (1)
            // 24: src_port (51038)
            // 25: dst_port (443)
            // 26: nat_src_port (32925)
            // 27: nat_dst_port (443)
            // 28: flags (0x42040d)
            // 29: protocol (tcp)
            // 30: action (allow)
            
            record.timestamp = parse_palo_alto_timestamp(fields.get(1).map(|s| s.as_str()).unwrap_or("")).unwrap_or_else(Utc::now);
            record.eventtime = parse_palo_alto_timestamp(fields.get(6).map(|s| s.as_str()).unwrap_or(""))
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(0);
            
            // Device information - will be set by device manager
            record.devname = String::new(); // Will be set from device manager
            record.devid = fields.get(2).map(|s| s.to_string()).unwrap_or_default(); // serial_number
            record.log_type = fields.get(3).map(|s| s.to_string()).unwrap_or_default(); // TRAFFIC
            record.subtype = fields.get(4).map(|s| s.to_string()).unwrap_or_else(|| "forward".to_string()); // end/start
            record.level = "info".to_string(); // Default level
            record.vd = fields.get(15).map(|s| s.to_string()).unwrap_or_default(); // virtual_system
            
            // Network information
            record.srcip = fields.get(7).map(|s| s.to_string()).unwrap_or_else(|| "0.0.0.0".to_string());
            record.dstip = fields.get(8).map(|s| s.to_string()).unwrap_or_else(|| "0.0.0.0".to_string());
            record.srcport = fields.get(24).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            record.dstport = fields.get(25).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            
            // Interface information
            record.srcintf = fields.get(18).map(|s| s.to_string()).unwrap_or_default(); // inbound_interface
            record.dstintf = fields.get(19).map(|s| s.to_string()).unwrap_or_default(); // outbound_interface
            record.srcintfrole = fields.get(16).map(|s| s.to_string()).unwrap_or_default(); // src_zone
            record.dstintfrole = fields.get(17).map(|s| s.to_string()).unwrap_or_default(); // dst_zone
            
            // Session information
            record.sessionid = fields.get(22).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            record.proto = map_protocol(fields.get(29).map(|s| s.as_str()).unwrap_or(""));
            record.action = fields.get(30).map(|s| s.to_string()).unwrap_or_default();
            
            // Policy information
            record.policyname = fields.get(11).map(|s| s.to_string()).unwrap_or_default(); // rule_name
            
            // Service/Application
            record.service = fields.get(14).map(|s| s.to_string()).unwrap_or_default(); // application
            
            // For fields beyond index 30, check if they exist
            if fields.len() > 31 {
                // Traffic statistics
                record.sentbyte = fields.get(31).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0); // bytes_total
                record.rcvdbyte = fields.get(32).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0); // bytes_sent
                if fields.len() > 33 {
                    record.sentpkt = fields.get(33).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0); // bytes_received
                }
                if fields.len() > 34 {
                    record.rcvdpkt = fields.get(34).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0); // packets_total
                }
            }
            
            // Set fields that may not be available in all logs
            record.srccountry = String::new(); // Will be filled if field exists in longer logs
            record.dstcountry = String::new();
            record.vpntype = String::new();
            
            // Set a generic log ID for Palo Alto
            record.logid = "0000000013".to_string(); // Generic traffic log ID
        } else {
            warn!("Palo Alto log has insufficient fields: {} (expected at least 30)", fields.len());
            return Err(anyhow::anyhow!("Insufficient fields in Palo Alto log"));
        }
        
        Ok(record)
    }
    
    pub fn validate(&self) -> bool {
        // Must have: non-empty message and device info
        let has_basic_info = !self.raw_message.is_empty() && 
                            (!self.devname.is_empty() || !self.devid.is_empty());
        
        // For traffic logs, require valid IP addresses
        let has_valid_traffic = if self.log_type == "TRAFFIC" {
            let srcip_valid = !self.srcip.is_empty() && self.srcip != "0.0.0.0";
            let dstip_valid = !self.dstip.is_empty() && self.dstip != "0.0.0.0";
            
            // Accept if at least one IP is valid
            srcip_valid || dstip_valid
        } else {
            true // Non-traffic logs don't need IP addresses
        };
        
        let valid = has_basic_info && has_valid_traffic;
        
        if !valid {
            debug!("Validation failed - type: '{}', srcip: '{}', dstip: '{}', devname: '{}', empty_msg: {}", 
                   self.log_type, self.srcip, self.dstip, self.devname, self.raw_message.is_empty());
        }
        
        valid
    }
    
    /// Set device information for this record
    pub fn set_device_info(&mut self, device_name: &str, device_ip: &str) {
        self.device_name = device_name.to_string();
        self.device_ip = device_ip.to_string();
        // Also set devname for validation
        self.devname = device_name.to_string();
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
                // Handle quoted fields
                if in_quotes {
                    if chars.peek() == Some(&'"') {
                        // Escaped quote
                        current_field.push('"');
                        chars.next(); // consume the second quote
                    } else {
                        // End of quoted field
                        in_quotes = false;
                    }
                } else {
                    // Start of quoted field
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                // Field separator
                fields.push(current_field.trim().to_string());
                current_field.clear();
            }
            _ => {
                // Regular character
                current_field.push(ch);
            }
        }
    }
    
    // Add the last field
    fields.push(current_field.trim().to_string());
    fields
}

fn map_protocol(protocol: &str) -> u32 {
    match protocol.to_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "igmp" => 2,
        "esp" => 50,
        "ah" => 51,
        "gre" => 47,
        "ipv6-icmp" => 58,
        _ => protocol.parse::<u32>().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_palo_alto_traffic_log() {
        // Sample Palo Alto traffic log (simplified)
        let log_line = r#"1,2024/01/15 10:30:45,012345678901,TRAFFIC,end,2049,2024/01/15 10:30:45,192.168.1.100,8.8.8.8,192.168.1.100,8.8.8.8,Allow-DNS,user1,,dns,vsys1,trust,untrust,ethernet1/1,ethernet1/2,Forward,2024/01/15 10:30:45,12345,1,53123,53,53123,53,0x400000,udp,allow,200,100,100,2,2024/01/15 10:30:42,3,any,0,123456,0x0,US,US,0,1,1,aged-out,1,2,3,4,vsys1,PA-VM,from-policy,,,,,,,,none,,,,rule-uuid"#;
        
        let record = PaloAltoRecord::parse(log_line).unwrap();
        
        assert_eq!(record.srcip, "192.168.1.100");
        assert_eq!(record.dstip, "8.8.8.8");
        assert_eq!(record.srcport, 53123);
        assert_eq!(record.dstport, 53);
        assert_eq!(record.proto, 17); // UDP
        assert_eq!(record.action, "allow");
        assert_eq!(record.policyname, "Allow-DNS");
        assert!(record.validate());
    }
    
    #[test]
    fn test_csv_field_parsing() {
        let log_with_quotes = r#"1,2024/01/15 10:30:45,012345678901,TRAFFIC,end,2049,2024/01/15 10:30:45,192.168.1.100,8.8.8.8,192.168.1.100,8.8.8.8,"Policy with, comma",user1,,dns,vsys1,trust,untrust,ethernet1/1,ethernet1/2,Forward,2024/01/15 10:30:45,12345,1,53123,53,53123,53,0x400000,tcp,allow,200,100,100,2,2024/01/15 10:30:42,3,any,0,123456,0x0,US,US,0,1,1,aged-out,1,2,3,4,vsys1,PA-VM,from-policy,,,,,,,,none,,,,rule-uuid"#;
        
        let record = PaloAltoRecord::parse(log_with_quotes).unwrap();
        assert_eq!(record.policyname, "Policy with, comma");
    }
}