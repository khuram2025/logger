use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info};

mod config;
mod fortigate;
mod paloalto;
mod clickhouse_client;
mod syslog;
mod device_manager_simple;

use config::Config;
use fortigate::FortiGateRecord;
use clickhouse_client::ClickHouseClient;
use syslog::SyslogReceiver;
use device_manager_simple::DeviceManager;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,
    
    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize tracing
    let level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("fortigate_syslog_rust={}", level))
        .init();
    
    info!("Starting FortiGate Syslog Rust Receiver");
    
    // Load configuration
    let config = Config::load(&args.config)?;
    info!("Configuration loaded from: {}", args.config);
    
    // Initialize ClickHouse client
    let ch_client = Arc::new(ClickHouseClient::new(&config).await?);
    info!("ClickHouse client initialized");
    
    // Initialize Device Manager
    let device_manager = Arc::new(DeviceManager::new());
    device_manager.load_devices().await?;
    info!("Device manager initialized");
    
    // Start periodic device refresh task
    DeviceManager::start_periodic_refresh(Arc::clone(&device_manager));
    info!("Device refresh task started (30 second interval)");
    
    // Create channels for communication
    let (tx, rx) = mpsc::channel::<FortiGateRecord>(config.buffer_size());
    
    // Start ClickHouse writer task
    let ch_writer = tokio::spawn({
        let client = Arc::clone(&ch_client);
        let batch_size = config.batch_size();
        let batch_timeout = config.batch_timeout();
        async move {
            clickhouse_writer_task(client, rx, batch_size, batch_timeout).await
        }
    });
    
    // Start syslog receiver with device manager
    let syslog_receiver = SyslogReceiver::new(config.clone());
    let receiver_task = tokio::spawn({
        let device_mgr = Arc::clone(&device_manager);
        async move {
            syslog_receiver.run(tx, device_mgr).await
        }
    });
    
    info!("All tasks started, waiting for shutdown signal...");
    
    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received Ctrl+C, shutting down gracefully...");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }
    
    // Cleanup
    receiver_task.abort();
    ch_writer.abort();
    
    info!("Shutdown complete");
    Ok(())
}

async fn clickhouse_writer_task(
    client: Arc<ClickHouseClient>,
    mut rx: mpsc::Receiver<FortiGateRecord>,
    batch_size: usize,
    batch_timeout: u64,
) -> Result<()> {
    let mut batch = Vec::with_capacity(batch_size);
    let mut last_flush = std::time::Instant::now();
    let timeout_duration = std::time::Duration::from_secs(batch_timeout);
    
    loop {
        tokio::select! {
            record = rx.recv() => {
                match record {
                    Some(record) => {
                        batch.push(record);
                        
                        if batch.len() >= batch_size {
                            if let Err(e) = client.insert_batch(&batch).await {
                                error!("Failed to insert batch: {:?}", e);
                            } else {
                                info!("Inserted batch of {} records", batch.len());
                            }
                            batch.clear();
                            last_flush = std::time::Instant::now();
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(last_flush + timeout_duration)) => {
                if !batch.is_empty() {
                    if let Err(e) = client.insert_batch(&batch).await {
                        error!("Failed to insert timeout batch: {:?}", e);
                    } else {
                        info!("Inserted timeout batch of {} records", batch.len());
                    }
                    batch.clear();
                    last_flush = std::time::Instant::now();
                }
            }
        }
    }
    
    // Flush remaining records
    if !batch.is_empty() {
        if let Err(e) = client.insert_batch(&batch).await {
            error!("Failed to insert final batch: {:?}", e);
        } else {
            info!("Inserted final batch of {} records", batch.len());
        }
    }
    
    Ok(())
}