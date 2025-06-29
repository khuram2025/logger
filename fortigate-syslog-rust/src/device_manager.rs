use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::clickhouse_client::ClickHouseClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDevice {
    pub device_ip: String,
    pub device_name: String,
    pub parser_type: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DeviceManager {
    devices: Arc<RwLock<HashMap<String, RegisteredDevice>>>,
    clickhouse_client: Arc<ClickHouseClient>,
}

impl DeviceManager {
    pub fn new(clickhouse_client: Arc<ClickHouseClient>) -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            clickhouse_client,
        }
    }

    /// Load registered devices from ClickHouse
    pub async fn load_devices(&self) -> Result<()> {
        info!("Loading registered devices from database...");
        
        let query = "SELECT device_ip, device_name, parser_type, enabled FROM network_logs.registered_devices WHERE enabled = 1 FORMAT JSONEachRow";
        
        // Use HTTP query for JSON results
        let url = format!("http://{}:{}", "localhost", 8123);
        let client = reqwest::Client::new();
        
        let result = client
            .post(&url)
            .query(&[("user", "default"), ("password", "Read@123")])
            .body(query)
            .send()
            .await;

        match result {
            Ok(response) => {
                match response.text().await {
                    Ok(text) => {
                        let mut devices = self.devices.write().await;
                        devices.clear();
                        
                        for line in text.lines() {
                            if line.trim().is_empty() {
                                continue;
                            }
                            
                            match serde_json::from_str::<RegisteredDevice>(line) {
                                Ok(device) => {
                                    debug!("Loaded device: {} ({})", device.device_name, device.device_ip);
                                    devices.insert(device.device_ip.clone(), device);
                                }
                                Err(e) => {
                                    warn!("Failed to parse device record: {} | Data: {}", e, line);
                                }
                            }
                        }
                        
                        info!("Loaded {} registered devices", devices.len());
                        Ok(())
                    }
                    Err(e) => {
                        error!("Failed to read response text: {}", e);
                        Err(e.into())
                    }
                }
            }
            Err(e) => {
                error!("Failed to load devices from database: {}", e);
                Err(e.into())
            }
        }
    }

    /// Check if a device is registered and enabled
    pub async fn is_device_registered(&self, source_ip: &str) -> bool {
        let devices = self.devices.read().await;
        devices.contains_key(source_ip) && devices.get(source_ip).unwrap().enabled
    }

    /// Get device information by IP
    pub async fn get_device(&self, source_ip: &str) -> Option<RegisteredDevice> {
        let devices = self.devices.read().await;
        devices.get(source_ip).cloned()
    }

    /// Get parser type for a device
    pub async fn get_parser_type(&self, source_ip: &str) -> Option<String> {
        let devices = self.devices.read().await;
        devices.get(source_ip).map(|d| d.parser_type.clone())
    }

    /// Reload devices from database (for API triggers)
    pub async fn reload_devices(&self) -> Result<()> {
        info!("Reloading devices from database...");
        self.load_devices().await
    }

    /// Get statistics about registered devices
    pub async fn get_device_stats(&self) -> HashMap<String, u64> {
        let devices = self.devices.read().await;
        let mut stats = HashMap::new();
        
        stats.insert("total_devices".to_string(), devices.len() as u64);
        stats.insert("enabled_devices".to_string(), 
                    devices.values().filter(|d| d.enabled).count() as u64);
        
        // Count by parser type
        for device in devices.values() {
            let key = format!("parser_{}", device.parser_type);
            *stats.entry(key).or_insert(0) += 1;
        }
        
        stats
    }
}

/// Test the device manager functionality
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_device_manager_basic() {
        // This would require a mock ClickHouse client for proper testing
        // For now, just test the data structures
        let device = RegisteredDevice {
            device_ip: "192.168.1.1".to_string(),
            device_name: "Test Device".to_string(),
            parser_type: "fortigate".to_string(),
            enabled: true,
        };
        
        assert_eq!(device.device_ip, "192.168.1.1");
        assert!(device.enabled);
    }
}