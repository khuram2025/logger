use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use anyhow::Result;
use lazy_static::lazy_static;
use tracing::{debug, warn};

lazy_static! {
    static ref KV_PATTERN: Regex = Regex::new(r#"(\w+)=(".*?"|[^\s]+)"#).unwrap();
}

// Numeric fields that should be parsed as integers
const NUMERIC_FIELDS: &[&str] = &[
    "eventtime", "srcport", "dstport", "sessionid", "proto", "policyid",
    "duration", "sentbyte", "rcvdbyte", "sentpkt", "rcvdpkt",
    "sentdelta", "rcvddelta", "durationdelta", "sentpktdelta", "rcvdpktdelta"
];

// IP address fields that need validation
const IP_FIELDS: &[&str] = &[
    "srcip", "dstip", "gateway", "nexthop", "dstserver", "srcserver",
    "assignip", "nat_ip", "transip", "unnip", "locip", "remip"
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortiGateRecord {
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

impl Default for FortiGateRecord {
    fn default() -> Self {
        FortiGateRecord {
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

impl FortiGateRecord {
    pub fn parse(line: &str) -> Result<Self> {
        let mut record = FortiGateRecord::default();
        record.raw_message = line.trim().to_string();
        
        // Parse key-value pairs
        let mut kv_pairs = HashMap::new();
        for caps in KV_PATTERN.captures_iter(line) {
            if let (Some(key), Some(value)) = (caps.get(1), caps.get(2)) {
                let key = key.as_str();
                let value = value.as_str().trim_matches('"');
                kv_pairs.insert(key, value);
            }
        }
        
        debug!("Parsed {} key-value pairs from log line", kv_pairs.len());
        
        // Parse timestamp from date and time fields
        record.timestamp = parse_timestamp(&kv_pairs).unwrap_or_else(Utc::now);
        
        // Parse string fields
        record.devname = kv_pairs.get("devname").unwrap_or(&"").to_string();
        record.devid = kv_pairs.get("devid").unwrap_or(&"").to_string();
        record.tz = kv_pairs.get("tz").unwrap_or(&"").to_string();
        record.logid = kv_pairs.get("logid").unwrap_or(&"").to_string();
        record.log_type = kv_pairs.get("type").unwrap_or(&"").to_string();
        record.subtype = kv_pairs.get("subtype").unwrap_or(&"").to_string();
        record.level = kv_pairs.get("level").unwrap_or(&"").to_string();
        record.vd = kv_pairs.get("vd").unwrap_or(&"").to_string();
        record.srcintf = kv_pairs.get("srcintf").unwrap_or(&"").to_string();
        record.srcintfrole = kv_pairs.get("srcintfrole").unwrap_or(&"").to_string();
        record.dstintf = kv_pairs.get("dstintf").unwrap_or(&"").to_string();
        record.dstintfrole = kv_pairs.get("dstintfrole").unwrap_or(&"").to_string();
        record.srccountry = kv_pairs.get("srccountry").unwrap_or(&"").to_string();
        record.dstcountry = kv_pairs.get("dstcountry").unwrap_or(&"").to_string();
        record.action = kv_pairs.get("action").unwrap_or(&"").to_string();
        record.policytype = kv_pairs.get("policytype").unwrap_or(&"").to_string();
        record.poluuid = kv_pairs.get("poluuid").unwrap_or(&"").to_string();
        record.policyname = kv_pairs.get("policyname").unwrap_or(&"").to_string();
        record.service = kv_pairs.get("service").unwrap_or(&"").to_string();
        record.trandisp = kv_pairs.get("trandisp").unwrap_or(&"").to_string();
        record.appcat = kv_pairs.get("appcat").unwrap_or(&"").to_string();
        record.vpntype = kv_pairs.get("vpntype").unwrap_or(&"").to_string();
        
        // Parse IP addresses with validation
        record.srcip = parse_ip_address(kv_pairs.get("srcip"));
        record.dstip = parse_ip_address(kv_pairs.get("dstip"));
        
        // Parse numeric fields with bounds checking
        record.eventtime = parse_numeric_u64(kv_pairs.get("eventtime"));
        record.srcport = parse_numeric_u32(kv_pairs.get("srcport"));
        record.dstport = parse_numeric_u32(kv_pairs.get("dstport"));
        record.sessionid = parse_numeric_u64(kv_pairs.get("sessionid"));
        record.proto = parse_numeric_u32(kv_pairs.get("proto"));
        record.policyid = parse_numeric_u32(kv_pairs.get("policyid"));
        record.duration = parse_numeric_u64(kv_pairs.get("duration"));
        record.sentbyte = parse_numeric_u64(kv_pairs.get("sentbyte"));
        record.rcvdbyte = parse_numeric_u64(kv_pairs.get("rcvdbyte"));
        record.sentpkt = parse_numeric_u64(kv_pairs.get("sentpkt"));
        record.rcvdpkt = parse_numeric_u64(kv_pairs.get("rcvdpkt"));
        record.sentdelta = parse_numeric_u64(kv_pairs.get("sentdelta"));
        record.rcvddelta = parse_numeric_u64(kv_pairs.get("rcvddelta"));
        record.durationdelta = parse_numeric_u64(kv_pairs.get("durationdelta"));
        record.sentpktdelta = parse_numeric_u64(kv_pairs.get("sentpktdelta"));
        record.rcvdpktdelta = parse_numeric_u64(kv_pairs.get("rcvdpktdelta"));
        
        Ok(record)
    }
    
    pub fn validate(&self) -> bool {
        // More flexible validation - accept logs with or without traffic data
        // Must have: non-empty message and device info
        let has_basic_info = !self.raw_message.is_empty() && 
                            (!self.devname.is_empty() || !self.devid.is_empty());
        
        // For traffic logs, require valid IP addresses (IPv4 or IPv6)
        let has_valid_traffic = if self.log_type == "traffic" {
            let srcip_valid = !self.srcip.is_empty() && self.srcip != "0.0.0.0";
            let dstip_valid = !self.dstip.is_empty() && self.dstip != "0.0.0.0";
            
            // Accept if at least one IP is valid (some logs might have internal/external traffic)
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
    }
}

fn parse_timestamp(kv_pairs: &HashMap<&str, &str>) -> Option<DateTime<Utc>> {
    let date = kv_pairs.get("date")?;
    let time = kv_pairs.get("time")?;
    
    let timestamp_str = format!("{} {}", date, time);
    
    match NaiveDateTime::parse_from_str(&timestamp_str, "%Y-%m-%d %H:%M:%S") {
        Ok(naive_dt) => Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc)),
        Err(e) => {
            warn!("Failed to parse timestamp '{}': {}", timestamp_str, e);
            None
        }
    }
}

fn parse_ip_address(ip_opt: Option<&&str>) -> String {
    match ip_opt {
        Some(ip_str) => {
            if ip_str.is_empty() {
                return "0.0.0.0".to_string();
            }
            
            // First try IPv4, then IPv6, then keep as string for other formats
            match Ipv4Addr::from_str(ip_str) {
                Ok(_) => ip_str.to_string(), // Valid IPv4
                Err(_) => {
                    // Check if it looks like IPv6
                    if ip_str.contains(':') {
                        // Keep IPv6 addresses as-is
                        debug!("Preserving IPv6 address: {}", ip_str);
                        ip_str.to_string()
                    } else {
                        warn!("Invalid IP address: {}", ip_str);
                        "0.0.0.0".to_string()
                    }
                }
            }
        }
        None => "0.0.0.0".to_string(),
    }
}

fn parse_numeric_u32(value_opt: Option<&&str>) -> u32 {
    match value_opt {
        Some(value_str) => {
            value_str.parse::<u32>().unwrap_or_else(|e| {
                warn!("Failed to parse u32 '{}': {}", value_str, e);
                0
            })
        }
        None => 0,
    }
}

fn parse_numeric_u64(value_opt: Option<&&str>) -> u64 {
    match value_opt {
        Some(value_str) => {
            value_str.parse::<u64>().unwrap_or_else(|e| {
                warn!("Failed to parse u64 '{}': {}", value_str, e);
                0
            })
        }
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_log() {
        let log_line = r#"date=2024-01-15 time=10:30:45 devname="FortiGate-100F" devid="FG100F1234567890" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1705310445 srcip=192.168.1.100 srcport=12345 srcintf="port1" srcintfrole="lan" dstip=8.8.8.8 dstport=53 dstintf="port2" dstintfrole="wan" proto=17 action="accept" policyid=1 service="DNS" duration=123 sentbyte=64 rcvdbyte=128 sentpkt=1 rcvdpkt=1"#;
        
        let record = FortiGateRecord::parse(log_line).unwrap();
        
        assert_eq!(record.srcip, "192.168.1.100");
        assert_eq!(record.dstip, "8.8.8.8");
        assert_eq!(record.srcport, 12345);
        assert_eq!(record.dstport, 53);
        assert_eq!(record.proto, 17);
        assert_eq!(record.action, "accept");
        assert!(record.validate());
    }
    
    #[test]
    fn test_parse_malformed_ips() {
        let log_line = r#"date=2024-01-15 time=10:30:45 srcip=invalid.ip dstip=999.999.999.999 srcport=12345"#;
        
        let record = FortiGateRecord::parse(log_line).unwrap();
        
        assert_eq!(record.srcip, "0.0.0.0");
        assert_eq!(record.dstip, "0.0.0.0");
        assert!(!record.validate()); // Should fail validation due to invalid IPs
    }
}