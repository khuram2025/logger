use fortigate_syslog_rust::{config::Config, paloalto_url::PaloAltoUrlRecord, clickhouse_url_client::ClickHouseUrlClient};
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .init();
        
    println!("Testing ClickHouse URL insertion...");
    
    // Load configuration
    let config = Config::load("config.toml")?;
    println!("✅ Configuration loaded");
    
    // Initialize ClickHouse URL client
    let client = ClickHouseUrlClient::new(&config).await?;
    println!("✅ ClickHouse URL client initialized");
    
    // Read and parse test log
    let test_log = fs::read_to_string("test_url_log.txt")?;
    let test_log = test_log.trim();
    
    let mut record = PaloAltoUrlRecord::parse(test_log)?;
    record.set_device_info("TEST-PA-DEVICE", "192.168.1.100");
    println!("✅ URL record parsed and device info set");
    
    // Test single record insertion
    client.insert_single(&record).await?;
    println!("✅ Single URL record inserted successfully");
    
    // Get stats
    match client.get_stats().await {
        Ok((count, last_timestamp)) => {
            println!("✅ Table stats: {} records, last timestamp: {}", count, last_timestamp);
        }
        Err(e) => {
            println!("⚠️  Could not get stats: {}", e);
        }
    }
    
    // Test health check
    match client.health_check().await {
        Ok(healthy) => {
            if healthy {
                println!("✅ ClickHouse health check passed");
            } else {
                println!("❌ ClickHouse health check failed");
            }
        }
        Err(e) => {
            println!("❌ Health check error: {}", e);
        }
    }
    
    println!("🎉 All tests completed!");
    
    Ok(())
}