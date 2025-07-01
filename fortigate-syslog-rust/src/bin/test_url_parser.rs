use fortigate_syslog_rust::paloalto_url::PaloAltoUrlRecord;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .init();
        
    // Read test log
    let test_log = fs::read_to_string("test_url_log.txt")?;
    let test_log = test_log.trim();
    
    println!("Testing URL log parsing with sample log:");
    println!("{}", test_log);
    println!();
    
    // Test URL log parsing
    match PaloAltoUrlRecord::parse(test_log) {
        Ok(record) => {
            println!("✅ Successfully parsed URL log!");
            println!("Log Type: {}", record.log_type);
            println!("Log Subtype: {}", record.log_subtype);
            println!("Source: {}", record.source_address);
            println!("Destination: {}", record.destination_address);
            println!("URL: {}", record.url);
            println!("URL Domain: {}", record.url_domain);
            println!("URL Path: {}", record.url_path);
            println!("Action: {}", record.action);
            println!("Category: {}", record.url_category);
            println!("Severity: {}", record.severity);
            println!("Application: {}", record.application);
            println!("Device Name: {}", record.device_name);
            println!("Rule Name: {}", record.rule_name);
            
            // Test validation
            if record.validate() {
                println!("✅ Record validation passed!");
            } else {
                println!("❌ Record validation failed!");
            }
        }
        Err(e) => {
            println!("❌ Failed to parse URL log: {}", e);
            return Err(e.into());
        }
    }
    
    println!();
    println!("Testing detection logic...");
    
    // Test detection
    if test_log.contains("THREAT,url") {
        println!("✅ URL log detection works!");
    } else {
        println!("❌ URL log detection failed!");
    }
    
    Ok(())
}