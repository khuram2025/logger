use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use std::str;
use std::sync::Arc;

use crate::config::Config;
use crate::fortigate::FortiGateRecord;
use crate::device_manager_simple::DeviceManager;

pub struct SyslogReceiver {
    config: Config,
}

impl SyslogReceiver {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
    
    pub async fn run(&self, tx: mpsc::Sender<FortiGateRecord>, device_manager: Arc<DeviceManager>) -> Result<()> {
        let bind_addr = format!("{}:{}", 
            self.config.syslog.bind_address, 
            self.config.syslog.bind_port
        );
        
        info!("Starting syslog receiver on {}", bind_addr);
        
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", bind_addr))?;
        
        info!("UDP socket bound successfully to {}", bind_addr);
        
        let mut buf = vec![0u8; self.config.syslog.buffer_size];
        let mut packets_received = 0u64;
        let mut packets_processed = 0u64;
        let mut packets_dropped = 0u64;
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    packets_received += 1;
                    
                    // Check if source IP is allowed (legacy config check)
                    if !self.is_source_allowed(&addr) {
                        debug!("Dropping packet from unauthorized source: {}", addr.ip());
                        packets_dropped += 1;
                        continue;
                    }
                    
                    // Check if device is registered in database
                    let source_ip = addr.ip().to_string();
                    if !device_manager.is_device_registered(&source_ip).await {
                        debug!("Dropping packet from unregistered device: {}", source_ip);
                        packets_dropped += 1;
                        continue;
                    }
                    
                    // Get device information
                    let device_info = device_manager.get_device(&source_ip).await;
                    
                    // Convert bytes to string
                    let raw_message = match str::from_utf8(&buf[..len]) {
                        Ok(msg) => msg,
                        Err(e) => {
                            warn!("Invalid UTF-8 in syslog message from {}: {}", addr.ip(), e);
                            packets_dropped += 1;
                            continue;
                        }
                    };
                    
                    debug!("Received {} bytes from {}: {}", len, addr.ip(), 
                           if raw_message.len() > 100 { 
                               format!("{}...", &raw_message[..100]) 
                           } else { 
                               raw_message.to_string() 
                           });
                    
                    // Remove syslog priority prefix if present (e.g., "<xxx>")
                    let clean_message = self.strip_syslog_priority(raw_message);
                    
                    // Parse log based on device parser type
                    let parser_type = device_info.as_ref().map(|d| d.parser_type.as_str()).unwrap_or("fortigate");
                    
                    match parser_type {
                        "fortigate" => {
                            match FortiGateRecord::parse(clean_message) {
                                Ok(mut record) => {
                                    // Set device information
                                    if let Some(device) = &device_info {
                                        record.set_device_info(&device.device_name, &device.device_ip);
                                    }
                                    
                                    if record.validate() {
                                        match tx.send(record).await {
                                    Ok(_) => {
                                        packets_processed += 1;
                                        
                                        // Log statistics every 1000 packets
                                        if packets_received % 1000 == 0 {
                                            info!("Statistics: received={}, processed={}, dropped={}", 
                                                  packets_received, packets_processed, packets_dropped);
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to send record to processing queue: {}", e);
                                        packets_dropped += 1;
                                    }
                                        }
                                    } else {
                                        debug!("Dropping invalid FortiGate record from {}", addr.ip());
                                        packets_dropped += 1;
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to parse FortiGate log from {}: {} | Message: {}", 
                                          addr.ip(), e, clean_message.chars().take(200).collect::<String>());
                                    packets_dropped += 1;
                                }
                            }
                        }
                        _ => {
                            warn!("Unsupported parser type '{}' for device {}", parser_type, source_ip);
                            packets_dropped += 1;
                        }
                    }
                }
                Err(e) => {
                    error!("Error receiving UDP packet: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
    
    fn is_source_allowed(&self, addr: &SocketAddr) -> bool {
        if self.config.syslog.allowed_sources.is_empty() {
            return true; // Allow all if no restrictions configured
        }
        
        let source_ip = addr.ip().to_string();
        self.config.syslog.allowed_sources.contains(&source_ip)
    }
    
    fn strip_syslog_priority<'a>(&self, message: &'a str) -> &'a str {
        // Remove RFC3164 priority prefix like "<134>" from the beginning
        if message.starts_with('<') {
            if let Some(end_pos) = message.find('>') {
                if end_pos < 10 { // Priority should be short
                    return &message[end_pos + 1..];
                }
            }
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, SyslogConfig};

    #[test]
    fn test_strip_syslog_priority() {
        let config = Config::default();
        let receiver = SyslogReceiver::new(config);
        
        let message_with_priority = "<134>Jan 15 10:30:45 FortiGate: date=2024-01-15 time=10:30:45";
        let message_without_priority = "date=2024-01-15 time=10:30:45";
        
        assert_eq!(
            receiver.strip_syslog_priority(message_with_priority),
            "Jan 15 10:30:45 FortiGate: date=2024-01-15 time=10:30:45"
        );
        
        assert_eq!(
            receiver.strip_syslog_priority(message_without_priority),
            "date=2024-01-15 time=10:30:45"
        );
    }
    
    #[test]
    fn test_source_allowed() {
        let mut config = Config::default();
        config.syslog.allowed_sources = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];
        
        let receiver = SyslogReceiver::new(config);
        
        let allowed_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let denied_addr: SocketAddr = "192.168.1.2:12345".parse().unwrap();
        
        assert!(receiver.is_source_allowed(&allowed_addr));
        assert!(!receiver.is_source_allowed(&denied_addr));
    }
}