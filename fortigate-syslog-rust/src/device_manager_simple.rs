use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use clickhouse::Client;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDevice {
    pub device_ip: String,
    pub device_name: String,
    pub parser_type: String,
    pub enabled: bool,
}

#[derive(Clone)]
pub struct DeviceManager {
    devices: Arc<RwLock<HashMap<String, RegisteredDevice>>>,
    clickhouse_client: Client,
}

impl DeviceManager {
    pub fn new() -> Self {
        // Initialize ClickHouse client
        let clickhouse_client = Client::default()
            .with_url("http://localhost:8123")
            .with_user("default")
            .with_password("Read@123")
            .with_database("network_logs");
        
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            clickhouse_client,
        }
    }

    /// Load registered devices from ClickHouse
    pub async fn load_devices(&self) -> Result<()> {
        info!("Loading registered devices from ClickHouse...");
        
        let mut devices_map = HashMap::new();
        
        // Query ClickHouse for registered devices
        match self.query_clickhouse_devices().await {
            Ok(clickhouse_devices) => {
                for device in clickhouse_devices {
                    if device.enabled {
                        devices_map.insert(device.device_ip.clone(), device);
                    }
                }
                info!("Successfully loaded {} enabled devices from ClickHouse", devices_map.len());
            }
            Err(e) => {
                warn!("Failed to load devices from ClickHouse: {}. Using fallback static configuration.", e);
                
                // Fallback to static configuration if ClickHouse is unavailable
                devices_map.insert("192.168.100.221".to_string(), RegisteredDevice {
                    device_ip: "192.168.100.221".to_string(),
                    device_name: "FortiGate-FW02".to_string(),
                    parser_type: "fortigate".to_string(),
                    enabled: true,
                });
            }
        }
        
        // Update the devices HashMap
        {
            let mut devices = self.devices.write().await;
            *devices = devices_map;
        }
        
        // Log loaded devices
        let devices = self.devices.read().await;
        info!("Loaded {} registered devices total", devices.len());
        
        for (ip, device) in devices.iter() {
            info!("Device: {} ({}) - {} parser, enabled: {}", 
                  device.device_name, ip, device.parser_type, device.enabled);
        }
        
        Ok(())
    }

    /// Query ClickHouse for registered devices
    async fn query_clickhouse_devices(&self) -> Result<Vec<RegisteredDevice>> {
        use reqwest;
        
        // Use HTTP client directly to avoid ClickHouse client library issues
        let client = reqwest::Client::new();
        let query = "SELECT device_ip, device_name, parser_type, enabled FROM network_logs.registered_devices WHERE enabled = 1 FORMAT JSONEachRow";
        
        let response = client
            .post("http://localhost:8123/")
            .basic_auth("default", Some("Read@123"))
            .body(query)
            .send()
            .await?;
        
        let text = response.text().await?;
        
        let mut devices = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            let json: serde_json::Value = serde_json::from_str(line)?;
            devices.push(RegisteredDevice {
                device_ip: json["device_ip"].as_str().unwrap_or("").to_string(),
                device_name: json["device_name"].as_str().unwrap_or("").to_string(),
                parser_type: json["parser_type"].as_str().unwrap_or("").to_string(),
                enabled: json["enabled"].as_u64().unwrap_or(0) == 1,
            });
        }
        
        Ok(devices)
    }

    /// Check if a device is registered and enabled
    pub async fn is_device_registered(&self, source_ip: &str) -> bool {
        let devices = self.devices.read().await;
        match devices.get(source_ip) {
            Some(device) => {
                debug!("Device {} found: {} (enabled: {})", source_ip, device.device_name, device.enabled);
                device.enabled
            },
            None => {
                debug!("Device {} not registered", source_ip);
                false
            }
        }
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

    /// Reload devices from ClickHouse database
    pub async fn reload_devices(&self) -> Result<()> {
        info!("Reloading devices from ClickHouse...");
        self.load_devices().await
    }

    /// Start periodic device refresh task
    pub fn start_periodic_refresh(device_manager: Arc<DeviceManager>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30)); // Refresh every 30 seconds
            
            loop {
                interval.tick().await;
                
                match device_manager.reload_devices().await {
                    Ok(_) => {
                        debug!("Device list refreshed successfully");
                    }
                    Err(e) => {
                        warn!("Failed to refresh device list: {}", e);
                    }
                }
            }
        });
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