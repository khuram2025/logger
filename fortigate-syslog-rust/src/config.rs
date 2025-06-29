use serde::{Deserialize, Serialize};
use std::fs;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub syslog: SyslogConfig,
    pub clickhouse: ClickHouseConfig,
    pub processing: ProcessingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyslogConfig {
    pub bind_address: String,
    pub bind_port: u16,
    pub buffer_size: usize,
    pub allowed_sources: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClickHouseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    pub table: String,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProcessingConfig {
    pub batch_size: usize,
    pub batch_timeout: u64,
    pub buffer_size: usize,
    pub worker_threads: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            syslog: SyslogConfig {
                bind_address: "0.0.0.0".to_string(),
                bind_port: 514,
                buffer_size: 65536,
                allowed_sources: vec![
                    "192.168.100.221".to_string(),
                    "10.16.5.254".to_string(),
                ],
            },
            clickhouse: ClickHouseConfig {
                host: "localhost".to_string(),
                port: 9000,
                user: "default".to_string(),
                password: "Read@123".to_string(),
                database: "network_logs".to_string(),
                table: "fortigate_traffic".to_string(),
                connection_timeout: 30,
            },
            processing: ProcessingConfig {
                batch_size: 500,
                batch_timeout: 1,
                buffer_size: 10000,
                worker_threads: 4,
            },
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        if std::path::Path::new(path).exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file: {}", path))?;
            
            toml::from_str(&content)
                .with_context(|| format!("Failed to parse config file: {}", path))
        } else {
            tracing::warn!("Config file not found: {}, using defaults", path);
            let default_config = Config::default();
            
            // Write default config for reference
            let default_content = toml::to_string_pretty(&default_config)
                .context("Failed to serialize default config")?;
            
            fs::write(path, default_content)
                .with_context(|| format!("Failed to write default config to: {}", path))?;
            
            tracing::info!("Created default config file: {}", path);
            Ok(default_config)
        }
    }
    
    // Convenience accessors
    pub fn batch_size(&self) -> usize {
        self.processing.batch_size
    }
    
    pub fn batch_timeout(&self) -> u64 {
        self.processing.batch_timeout  
    }
    
    pub fn buffer_size(&self) -> usize {
        self.processing.buffer_size
    }
}