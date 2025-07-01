use fortigate_syslog_rust::{device_manager_simple::DeviceManager, paloalto_url::PaloAltoUrlRecord, paloalto::PaloAltoRecord};
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .init();
        
    println!("Testing full routing logic...");
    
    // Initialize device manager
    let device_manager = DeviceManager::new();
    device_manager.load_devices().await?;
    
    // Test with the problematic IP
    let test_ip = "10.10.100.4";
    
    println!("Testing device lookup for IP: {}", test_ip);
    
    // Check if device is registered
    if device_manager.is_device_registered(test_ip).await {
        println!("✅ Device {} is registered", test_ip);
        
        // Get device info
        if let Some(device_info) = device_manager.get_device(test_ip).await {
            println!("✅ Device info retrieved:");
            println!("  Name: {}", device_info.device_name);
            println!("  IP: {}", device_info.device_ip);
            println!("  Parser Type: {}", device_info.parser_type);
            println!("  Enabled: {}", device_info.enabled);
            
            // Test the routing logic
            let parser_type = device_info.parser_type.as_str();
            println!("✅ Parser type determined: {}", parser_type);
            
            // Read test log
            let test_log = fs::read_to_string("test_new_url_log.txt")?;
            let test_log = test_log.trim();
            
            // Strip syslog priority like the real parser does
            let clean_message = if test_log.starts_with('<') {
                if let Some(end_pos) = test_log.find('>') {
                    if end_pos < 10 {
                        &test_log[end_pos + 1..]
                    } else {
                        test_log
                    }
                } else {
                    test_log
                }
            } else {
                test_log
            };
            
            println!("Testing routing with parser type: {}", parser_type);
            
            match parser_type {
                "paloalto" => {
                    println!("✅ Routed to paloalto parser");
                    
                    // Test URL detection
                    if clean_message.contains("THREAT,url") {
                        println!("✅ URL log detected");
                        
                        match PaloAltoUrlRecord::parse(clean_message) {
                            Ok(record) => {
                                println!("✅ URL parsing successful!");
                                println!("  Would go to pa_urls_optimized table");
                                println!("  URL: {}", record.url);
                                println!("  Action: {}", record.action);
                            }
                            Err(e) => {
                                println!("❌ URL parsing failed: {}", e);
                            }
                        }
                    } else {
                        println!("⚠️  Not a URL log, would try traffic parsing");
                        match PaloAltoRecord::parse(clean_message) {
                            Ok(record) => {
                                println!("✅ Traffic parsing successful!");
                                println!("  Would go to fortigate_traffic table");
                            }
                            Err(e) => {
                                println!("❌ Traffic parsing failed: {}", e);
                            }
                        }
                    }
                }
                "fortigate" => {
                    println!("❌ Incorrectly routed to fortigate parser!");
                    println!("  This explains why URL logs go to fortigate_traffic table");
                }
                _ => {
                    println!("❌ Unknown parser type: {}", parser_type);
                }
            }
        } else {
            println!("❌ Failed to get device info despite being registered");
        }
    } else {
        println!("❌ Device {} is not registered", test_ip);
    }
    
    // Also test what would happen with an unregistered IP that might be the actual source
    println!("\nTesting potential other source IPs...");
    for test_source in &["10.16.5.254", "192.168.100.221"] {
        println!("Checking {}", test_source);
        if device_manager.is_device_registered(test_source).await {
            if let Some(device_info) = device_manager.get_device(test_source).await {
                println!("  Registered as: {} ({})", device_info.device_name, device_info.parser_type);
            }
        } else {
            println!("  Not registered");
        }
    }
    
    Ok(())
}