use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::paloalto_url::PaloAltoUrlRecord;

/// Escape string for ClickHouse SQL to prevent query injection and parameter confusion
fn escape_clickhouse_string(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('\'', "''")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

pub struct ClickHouseUrlClient {
    database: String,
    table: String,
    http_client: reqwest::Client,
    url: String,
    auth: (String, String),
}

impl ClickHouseUrlClient {
    pub async fn new(config: &Config) -> Result<Self> {
        let url = format!("http://{}:{}", config.clickhouse.host, config.clickhouse.port);
        let table = "pa_urls_optimized";
        
        info!("Connecting to ClickHouse at {} for URL logs", url);
        
        let http_client = reqwest::Client::new();
        let auth = (config.clickhouse.user.clone(), config.clickhouse.password.clone());
        
        // Test connection
        let response = http_client
            .post(&format!("{}/?database={}", url, config.clickhouse.database))
            .basic_auth(&auth.0, Some(&auth.1))
            .body("SELECT version()")
            .send()
            .await
            .context("Failed to connect to ClickHouse")?;
            
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to connect to ClickHouse: {}", response.status()));
        }
        
        let version = response.text().await.unwrap_or_else(|_| "Unknown".to_string());
        info!("Connected to ClickHouse version: {}", version);
        
        // Verify URL table exists
        let response = http_client
            .post(&format!("{}/?database={}", url, config.clickhouse.database))
            .basic_auth(&auth.0, Some(&auth.1))
            .body(format!(
                "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                config.clickhouse.database, table
            ))
            .send()
            .await
            .context("Failed to check if URL table exists")?;
            
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to check URL table existence"));
        }
        
        let table_exists: u64 = response.text().await?.trim().parse().unwrap_or(0);
        if table_exists == 0 {
            warn!("Table {}.{} does not exist. Please create it first.", 
                  config.clickhouse.database, table);
            return Err(anyhow::anyhow!("URL table does not exist"));
        }
        
        info!("Verified table {}.{} exists", config.clickhouse.database, table);
        
        Ok(ClickHouseUrlClient {
            database: config.clickhouse.database.clone(),
            table: table.to_string(),
            http_client,
            url,
            auth,
        })
    }
    
    pub async fn insert_batch(&self, records: &[PaloAltoUrlRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        
        debug!("Inserting batch of {} URL records", records.len());
        
        let mut values = Vec::new();
        for record in records {
            let value = format!(
                "('{}', '{}', '{}', '{}', {}, {}, '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, '{}', '{}', '{}', '{}', {}, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')",
                record.timestamp.format("%Y-%m-%d %H:%M:%S"),
                record.receive_time.format("%Y-%m-%d %H:%M:%S"),
                record.generated_time.format("%Y-%m-%d %H:%M:%S"),
                record.processing_timestamp.format("%Y-%m-%d %H:%M:%S"),
                record.sequence_number,
                record.session_id,
                escape_clickhouse_string(&record.device_name),
                escape_clickhouse_string(&record.serial_number),
                escape_clickhouse_string(&record.source_address),
                escape_clickhouse_string(&record.destination_address),
                escape_clickhouse_string(&record.nat_source_ip),
                escape_clickhouse_string(&record.nat_destination_ip),
                record.source_port,
                record.destination_port,
                escape_clickhouse_string(&record.source_zone),
                escape_clickhouse_string(&record.destination_zone),
                escape_clickhouse_string(&record.inbound_interface),
                escape_clickhouse_string(&record.outbound_interface),
                record.ip_protocol,
                escape_clickhouse_string(&record.protocol),
                escape_clickhouse_string(&record.url),
                escape_clickhouse_string(&record.url_domain),
                escape_clickhouse_string(&record.url_path),
                escape_clickhouse_string(&record.url_query),
                escape_clickhouse_string(&record.url_category),
                escape_clickhouse_string(&record.url_category_list),
                escape_clickhouse_string(&record.http_method),
                escape_clickhouse_string(&record.user_agent),
                escape_clickhouse_string(&record.referer),
                escape_clickhouse_string(&record.content_type),
                record.response_code,
                record.response_size,
                escape_clickhouse_string(&record.rule_name),
                escape_clickhouse_string(&record.rule_uuid),
                escape_clickhouse_string(&record.action),
                escape_clickhouse_string(&record.severity),
                escape_clickhouse_string(&record.direction),
                escape_clickhouse_string(&record.threat_id),
                escape_clickhouse_string(&record.threat_category),
                escape_clickhouse_string(&record.log_action),
                escape_clickhouse_string(&record.source_user),
                escape_clickhouse_string(&record.destination_user),
                escape_clickhouse_string(&record.application),
                escape_clickhouse_string(&record.application_category),
                escape_clickhouse_string(&record.source_country),
                escape_clickhouse_string(&record.destination_country),
                escape_clickhouse_string(&record.raw_message),
                escape_clickhouse_string(&record.log_type),
                escape_clickhouse_string(&record.log_subtype),
                escape_clickhouse_string(&record.virtual_system)
            );
            values.push(value);
        }
        
        let columns = "timestamp,receive_time,generated_time,processing_timestamp,sequence_number,session_id,device_name,serial_number,source_address,destination_address,nat_source_ip,nat_destination_ip,source_port,destination_port,source_zone,destination_zone,inbound_interface,outbound_interface,ip_protocol,protocol,url,url_domain,url_path,url_query,url_category,url_category_list,http_method,user_agent,referer,content_type,response_code,response_size,rule_name,rule_uuid,action,severity,direction,threat_id,threat_category,log_action,source_user,destination_user,application,application_category,source_country,destination_country,raw_message,log_type,log_subtype,virtual_system";
        
        let query = format!(
            "INSERT INTO {}.{} ({}) VALUES {}",
            self.database,
            self.table,
            columns,
            values.join(",")
        );
        
        let response = self.http_client
            .post(&format!("{}/?database={}", self.url, self.database))
            .basic_auth(&self.auth.0, Some(&self.auth.1))
            .body(query)
            .send()
            .await
            .with_context(|| format!("Failed to send HTTP request for batch of {} URL records", records.len()))?;
            
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow::anyhow!("ClickHouse HTTP request failed: {}", error_text));
        }
            
        debug!("Successfully inserted batch of {} URL records", records.len());
        Ok(())
    }
    
    pub async fn insert_single(&self, record: &PaloAltoUrlRecord) -> Result<()> {
        self.insert_batch(&[record.clone()]).await
    }
    
    pub async fn get_stats(&self) -> Result<(u64, String)> {
        // Get count
        let count_response = self.http_client
            .post(&format!("{}/?database={}", self.url, self.database))
            .basic_auth(&self.auth.0, Some(&self.auth.1))
            .body(format!("SELECT count() FROM {}.{}", self.database, self.table))
            .send()
            .await
            .context("Failed to get URL record count")?;
        let count: u64 = count_response.text().await?.trim().parse().unwrap_or(0);
        
        // Get last timestamp
        let timestamp_response = self.http_client
            .post(&format!("{}/?database={}", self.url, self.database))
            .basic_auth(&self.auth.0, Some(&self.auth.1))
            .body(format!("SELECT toString(max(timestamp)) FROM {}.{}", self.database, self.table))
            .send()
            .await;
        let last_timestamp = match timestamp_response {
            Ok(resp) => resp.text().await.unwrap_or_else(|_| "N/A".to_string()).trim().to_string(),
            Err(_) => "N/A".to_string()
        };
            
        Ok((count, last_timestamp))
    }
    
    pub async fn health_check(&self) -> Result<bool> {
        match self.http_client
            .post(&format!("{}/?database={}", self.url, self.database))
            .basic_auth(&self.auth.0, Some(&self.auth.1))
            .body("SELECT 1")
            .send()
            .await {
            Ok(response) => Ok(response.status().is_success()),
            Err(e) => {
                error!("ClickHouse URL client health check failed: {}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ClickHouseConfig};
    use chrono::Utc;

    fn create_test_url_record() -> PaloAltoUrlRecord {
        PaloAltoUrlRecord {
            timestamp: Utc::now(),
            raw_message: "test URL message".to_string(),
            device_name: "test-pa-device".to_string(),
            source_address: "192.168.1.1".to_string(),
            destination_address: "8.8.8.8".to_string(),
            url: "https://example.com/path?query=test".to_string(),
            url_domain: "example.com".to_string(),
            url_path: "/path".to_string(),
            url_query: "query=test".to_string(),
            action: "alert".to_string(),
            ..Default::default()
        }
    }
    
    #[test]
    fn test_escape_clickhouse_string() {
        let input = "test'string\\with\nnewline\tand\rcarriage";
        let expected = "test''string\\\\with\\nnewline\\tand\\rcarriage";
        assert_eq!(escape_clickhouse_string(input), expected);
    }
}