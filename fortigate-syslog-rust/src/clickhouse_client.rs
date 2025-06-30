use anyhow::{Context, Result};
use clickhouse::{Client, Row};
use serde::Serialize;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::fortigate::FortiGateRecord;

/// Escape string for ClickHouse SQL to prevent query injection and parameter confusion
fn escape_clickhouse_string(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('\'', "''")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

#[derive(Row, Serialize)]
struct ClickHouseRecord<'a> {
    timestamp: &'a chrono::DateTime<chrono::Utc>,
    raw_message: &'a str,
    devname: &'a str,
    devid: &'a str,
    eventtime: u64,
    tz: &'a str,
    logid: &'a str,
    #[serde(rename = "type")]
    log_type: &'a str,
    subtype: &'a str,
    level: &'a str,
    vd: &'a str,
    srcip: &'a str,
    srcport: u16,
    srcintf: &'a str,
    srcintfrole: &'a str,
    dstip: &'a str,
    dstport: u16,
    dstintf: &'a str,
    dstintfrole: &'a str,
    srccountry: &'a str,
    dstcountry: &'a str,
    username: &'a str,
    sessionid: u64,
    proto: u8,
    action: &'a str,
    policyid: u32,
    policytype: &'a str,
    poluuid: &'a str,
    policyname: &'a str,
    service: &'a str,
    trandisp: &'a str,
    appcat: &'a str,
    duration: u32,
    sentbyte: u64,
    rcvdbyte: u64,
    sentpkt: u32,
    rcvdpkt: u32,
    sentdelta: u32,
    rcvddelta: u32,
    durationdelta: u32,
    sentpktdelta: u32,
    rcvdpktdelta: u32,
    vpntype: &'a str,
    device_name: &'a str,
    device_ip: &'a str,
}

impl<'a> From<&'a FortiGateRecord> for ClickHouseRecord<'a> {
    fn from(record: &'a FortiGateRecord) -> Self {
        ClickHouseRecord {
            timestamp: &record.timestamp,
            raw_message: &record.raw_message,
            devname: &record.devname,
            devid: &record.devid,
            eventtime: record.eventtime,
            tz: &record.tz,
            logid: &record.logid,
            log_type: &record.log_type,
            subtype: &record.subtype,
            level: &record.level,
            vd: &record.vd,
            srcip: &record.srcip,
            srcport: record.srcport as u16,
            srcintf: &record.srcintf,
            srcintfrole: &record.srcintfrole,
            dstip: &record.dstip,
            dstport: record.dstport as u16,
            dstintf: &record.dstintf,
            dstintfrole: &record.dstintfrole,
            srccountry: &record.srccountry,
            dstcountry: &record.dstcountry,
            username: "", // Add empty username field
            sessionid: record.sessionid,
            proto: record.proto as u8,
            action: &record.action,
            policyid: record.policyid,
            policytype: &record.policytype,
            poluuid: &record.poluuid,
            policyname: &record.policyname,
            service: &record.service,
            trandisp: &record.trandisp,
            appcat: &record.appcat,
            duration: record.duration as u32,
            sentbyte: record.sentbyte,
            rcvdbyte: record.rcvdbyte,
            sentpkt: record.sentpkt as u32,
            rcvdpkt: record.rcvdpkt as u32,
            sentdelta: record.sentdelta as u32,
            rcvddelta: record.rcvddelta as u32,
            durationdelta: record.durationdelta as u32,
            sentpktdelta: record.sentpktdelta as u32,
            rcvdpktdelta: record.rcvdpktdelta as u32,
            vpntype: &record.vpntype,
            device_name: &record.device_name,
            device_ip: &record.device_ip,
        }
    }
}

pub struct ClickHouseClient {
    client: Client,
    database: String,
    table: String,
}

impl ClickHouseClient {
    pub async fn new(config: &Config) -> Result<Self> {
        let url = format!("http://{}:{}", config.clickhouse.host, config.clickhouse.port);
        
        info!("Connecting to ClickHouse at {}", url);
        
        let client = Client::default()
            .with_url(url)
            .with_user(&config.clickhouse.user)
            .with_password(&config.clickhouse.password)
            .with_database(&config.clickhouse.database)
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "1")
            .with_option("date_time_input_format", "best_effort");
            
        // Test connection
        let result: String = client
            .query("SELECT version()")
            .fetch_one()
            .await
            .context("Failed to connect to ClickHouse")?;
            
        info!("Connected to ClickHouse version: {}", result);
        
        // Verify table exists
        let table_exists: u64 = client
            .query(&format!(
                "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                config.clickhouse.database, config.clickhouse.table
            ))
            .fetch_one()
            .await
            .context("Failed to check if table exists")?;
            
        if table_exists == 0 {
            warn!("Table {}.{} does not exist. Please create it first.", 
                  config.clickhouse.database, config.clickhouse.table);
            return Err(anyhow::anyhow!("Table does not exist"));
        }
        
        info!("Verified table {}.{} exists", config.clickhouse.database, config.clickhouse.table);
        
        Ok(ClickHouseClient {
            client,
            database: config.clickhouse.database.clone(),
            table: config.clickhouse.table.clone(),
        })
    }
    
    pub async fn insert_batch(&self, records: &[FortiGateRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        
        debug!("Inserting batch of {} records", records.len());
        
        // Use SQL INSERT instead of binary protocol to avoid schema mismatch
        let mut values = Vec::new();
        for record in records {
            let value = format!(
                "('{}', '{}', '{}', '{}', {}, '{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, '{}', '{}', '{}', {}, '{}', '{}', '{}', '{}', '', {}, {}, '{}', {}, '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, '{}', '{}', '{}')",
                record.timestamp.format("%Y-%m-%d %H:%M:%S"),
                escape_clickhouse_string(&record.raw_message),
                escape_clickhouse_string(&record.devname),
                escape_clickhouse_string(&record.devid),
                record.eventtime,
                escape_clickhouse_string(&record.tz),
                escape_clickhouse_string(&record.logid),
                escape_clickhouse_string(&record.log_type),
                escape_clickhouse_string(&record.subtype),
                escape_clickhouse_string(&record.level),
                escape_clickhouse_string(&record.vd),
                escape_clickhouse_string(&record.srcip),
                record.srcport,
                escape_clickhouse_string(&record.srcintf),
                escape_clickhouse_string(&record.srcintfrole),
                escape_clickhouse_string(&record.dstip),
                record.dstport,
                escape_clickhouse_string(&record.dstintf),
                escape_clickhouse_string(&record.dstintfrole),
                escape_clickhouse_string(&record.srccountry),
                escape_clickhouse_string(&record.dstcountry),
                // username (empty for now)
                record.sessionid,
                record.proto,
                escape_clickhouse_string(&record.action),
                record.policyid,
                escape_clickhouse_string(&record.policytype),
                escape_clickhouse_string(&record.poluuid),
                escape_clickhouse_string(&record.policyname),
                escape_clickhouse_string(&record.service),
                escape_clickhouse_string(&record.trandisp),
                escape_clickhouse_string(&record.appcat),
                record.duration,
                record.sentbyte,
                record.rcvdbyte,
                record.sentpkt,
                record.rcvdpkt,
                record.sentdelta,
                record.rcvddelta,
                record.durationdelta,
                record.sentpktdelta,
                record.rcvdpktdelta,
                escape_clickhouse_string(&record.vpntype),
                escape_clickhouse_string(&record.device_name),
                escape_clickhouse_string(&record.device_ip)
            );
            values.push(value);
        }
        
        let columns = "timestamp,raw_message,devname,devid,eventtime,tz,logid,type,subtype,level,vd,srcip,srcport,srcintf,srcintfrole,dstip,dstport,dstintf,dstintfrole,srccountry,dstcountry,username,sessionid,proto,action,policyid,policytype,poluuid,policyname,service,trandisp,appcat,duration,sentbyte,rcvdbyte,sentpkt,rcvdpkt,sentdelta,rcvddelta,durationdelta,sentpktdelta,rcvdpktdelta,vpntype,device_name,device_ip";
        let query = format!(
            "INSERT INTO {}.{} ({}) VALUES {}",
            self.database,
            self.table,
            columns,
            values.join(",")
        );
        
        self.client.query(&query).execute().await
            .with_context(|| format!("Failed to insert batch of {} records", records.len()))?;
            
        debug!("Successfully inserted batch of {} records", records.len());
        Ok(())
    }
    
    pub async fn insert_single(&self, record: &FortiGateRecord) -> Result<()> {
        self.insert_batch(&[record.clone()]).await
    }
    
    pub async fn get_stats(&self) -> Result<(u64, String)> {
        let count: u64 = self.client
            .query(&format!("SELECT count() FROM {}.{}", self.database, self.table))
            .fetch_one()
            .await
            .context("Failed to get record count")?;
            
        let last_timestamp: String = self.client
            .query(&format!(
                "SELECT toString(max(timestamp)) FROM {}.{}", 
                self.database, self.table
            ))
            .fetch_one()
            .await
            .unwrap_or_else(|_| "N/A".to_string());
            
        Ok((count, last_timestamp))
    }
    
    pub async fn health_check(&self) -> Result<bool> {
        match self.client.query("SELECT 1").fetch_one::<u8>().await {
            Ok(_) => Ok(true),
            Err(e) => {
                error!("ClickHouse health check failed: {}", e);
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

    fn create_test_record() -> FortiGateRecord {
        FortiGateRecord {
            timestamp: Utc::now(),
            raw_message: "test message".to_string(),
            devname: "test-device".to_string(),
            devid: "test-id".to_string(),
            srcip: "192.168.1.1".to_string(),
            dstip: "8.8.8.8".to_string(),
            srcport: 12345,
            dstport: 80,
            proto: 6,
            action: "accept".to_string(),
            ..Default::default()
        }
    }
    
    #[test]
    fn test_clickhouse_record_conversion() {
        let record = create_test_record();
        let ch_record = ClickHouseRecord::from(&record);
        
        assert_eq!(ch_record.devname, "test-device");
        assert_eq!(ch_record.srcip, "192.168.1.1");
        assert_eq!(ch_record.dstip, "8.8.8.8");
        assert_eq!(ch_record.srcport, 12345);
        assert_eq!(ch_record.dstport, 80);
    }
}