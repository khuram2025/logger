use fortigate_syslog_rust::paloalto_url::PaloAltoUrlRecord;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .init();
        
    // Read the problematic log
    let test_log = fs::read_to_string("test_new_url_log.txt")?;
    let test_log = test_log.trim();
    
    println!("Debugging URL log detection...");
    println!("Raw log: {}", test_log);
    println!();
    
    // Test detection logic
    println!("Detection tests:");
    println!("Contains 'THREAT,url': {}", test_log.contains("THREAT,url"));
    
    // Strip syslog header like the actual parser does
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
    
    println!("After syslog strip: {}", clean_message);
    println!("Clean message contains 'THREAT,url': {}", clean_message.contains("THREAT,url"));
    println!();
    
    // Try parsing with URL parser
    println!("Testing URL parser...");
    match PaloAltoUrlRecord::parse(clean_message) {
        Ok(record) => {
            println!("✅ URL parsing successful!");
            println!("  Log Type: {}", record.log_type);
            println!("  Log Subtype: {}", record.log_subtype);
            println!("  URL: {}", record.url);
            println!("  URL Domain: {}", record.url_domain);
            println!("  Action: {}", record.action);
            println!("  Application: {}", record.application);
            
            if record.validate() {
                println!("✅ Validation passed");
            } else {
                println!("❌ Validation failed");
            }
        }
        Err(e) => {
            println!("❌ URL parsing failed: {}", e);
        }
    }
    
    // Check CSV parsing
    println!();
    println!("Checking CSV structure...");
    let csv_part = if let Some(start_pos) = clean_message.find(char::is_numeric) {
        &clean_message[start_pos..]
    } else {
        clean_message
    };
    
    println!("CSV part: {}", &csv_part[..200.min(csv_part.len())]);
    
    // Parse fields to see structure
    let fields: Vec<String> = parse_csv_fields(csv_part);
    println!("Total fields: {}", fields.len());
    
    if fields.len() >= 5 {
        println!("Field 3 (type): '{}'", fields.get(3).unwrap_or(&"".to_string()));
        println!("Field 4 (subtype): '{}'", fields.get(4).unwrap_or(&"".to_string()));
    }
    
    Ok(())
}

fn parse_csv_fields(csv_line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;
    let mut chars = csv_line.chars().peekable();
    
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    if chars.peek() == Some(&'"') {
                        current_field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(current_field.trim().to_string());
                current_field.clear();
            }
            _ => {
                current_field.push(ch);
            }
        }
    }
    
    fields.push(current_field.trim().to_string());
    fields
}