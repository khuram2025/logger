use fortigate_syslog_rust::paloalto::PaloAltoRecord;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .init();
    
    // Sample log from 10.10.100.2
    let sample_log = "Jul  3 14:21:27 SMO-RUH-MU04-F09R14-DC-FW1.smo.sa 1,2025/07/03 14:21:27,025201005457,TRAFFIC,end,2817,2025/07/03 14:21:27,10.10.200.21,10.10.108.20,0.0.0.0,0.0.0.0,From_Users_Or_Servers_To_LDAP,smo\\ra.almasoud,,incomplete,vsys1,SMO-WIFI-EMPLOYEE,SERVER,ae1.201,ae3.108,H_SMO_LFP,2025/07/03 14:21:27,4319108,1,59781,389,0,0,0x1b,tcp,allow,388,190,198,6,2025/07/03 14:21:11,0,any,,7502587801701290874,0x8000000000000000,10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,,3,3,tcp-rst-from-server,210,70,0,0,,SMO-RUH-MU04-F09R14-DC-FW1,from-policy,,,0,,0,,N/A,0,0,0,0,5f5c3012-7352-4dce-8e5b-ef5d82150ec3,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2025-07-03T14:21:27.945+03:00,,,unknown,unknown,unknown,1,,,incomplete,no,no,0,NonProxyTraffic,";
    
    println!("Testing Palo Alto log parsing...");
    println!("Log sample: {}...", &sample_log[..100]);
    
    match PaloAltoRecord::parse(sample_log) {
        Ok(mut record) => {
            println!("\n✓ Parsing successful!");
            println!("  Log type: {}", record.log_type);
            println!("  Source IP: {}", record.srcip);
            println!("  Dest IP: {}", record.dstip);
            println!("  Device ID: {}", record.devid);
            println!("  Device name: {}", record.devname);
            
            // Test validation before setting device info
            println!("\nValidation before set_device_info: {}", record.validate());
            
            // Set device info
            record.set_device_info("SMO-RUH-DC-FW01", "10.10.100.2");
            println!("\nAfter set_device_info:");
            println!("  Device name: {}", record.devname);
            println!("  Device IP: {}", record.device_ip);
            
            // Test validation after setting device info
            println!("\nValidation after set_device_info: {}", record.validate());
        }
        Err(e) => {
            println!("\n✗ Parsing failed: {}", e);
        }
    }
}