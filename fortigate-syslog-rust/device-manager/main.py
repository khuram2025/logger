#!/usr/bin/env python3
"""
Device Manager API for FortiGate Syslog System
Provides web interface to register devices and manage log sources
"""

from flask import Flask, request, jsonify, render_template_string
import requests
import json
from datetime import datetime

app = Flask(__name__)

# ClickHouse configuration
CLICKHOUSE_HOST = "localhost"
CLICKHOUSE_PORT = 8123
CLICKHOUSE_USER = "default"
CLICKHOUSE_PASSWORD = "Read@123"

def clickhouse_query(query):
    """Execute ClickHouse query"""
    url = f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}/"
    params = {
        'user': CLICKHOUSE_USER,
        'password': CLICKHOUSE_PASSWORD
    }
    response = requests.post(url, params=params, data=query)
    if response.status_code == 200:
        return response.text.strip()
    else:
        raise Exception(f"ClickHouse error: {response.text}")

@app.route('/logs-sources/add/', methods=['GET', 'POST'])
def add_log_source():
    """Add new log source device"""
    if request.method == 'GET':
        # Return HTML form
        html_form = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Add Log Source Device</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .form-group { margin: 15px 0; }
                label { display: block; margin-bottom: 5px; font-weight: bold; }
                input, select { width: 300px; padding: 8px; font-size: 14px; }
                button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
                button:hover { background: #005a87; }
                .success { color: green; padding: 10px; background: #e7f5e7; border: 1px solid green; margin: 10px 0; }
                .error { color: red; padding: 10px; background: #ffe7e7; border: 1px solid red; margin: 10px 0; }
            </style>
        </head>
        <body>
            <h1>Add Log Source Device</h1>
            <form method="POST" action="/logs-sources/add/">
                <div class="form-group">
                    <label for="device_ip">Device IP Address:</label>
                    <input type="text" id="device_ip" name="device_ip" required 
                           placeholder="e.g., 192.168.100.221" pattern="[0-9.:]+">
                </div>
                <div class="form-group">
                    <label for="device_name">Device Name:</label>
                    <input type="text" id="device_name" name="device_name" required 
                           placeholder="e.g., FortiGate-FW01">
                </div>
                <div class="form-group">
                    <label for="parser_type">Parser Type:</label>
                    <select id="parser_type" name="parser_type" required>
                        <option value="fortigate">FortiGate</option>
                        <option value="paloalto">Palo Alto</option>
                        <option value="cisco">Cisco ASA</option>
                        <option value="generic">Generic Syslog</option>
                    </select>
                </div>
                <div class="form-group">
                    <button type="submit">Add Device</button>
                </div>
            </form>
            
            <h2>Registered Devices</h2>
            <div id="devices-list">
                <!-- Will be populated by JavaScript -->
            </div>
            
            <script>
                // Load registered devices
                fetch('/api/devices')
                    .then(response => response.json())
                    .then(devices => {
                        const list = document.getElementById('devices-list');
                        if (devices.length === 0) {
                            list.innerHTML = '<p>No devices registered yet.</p>';
                        } else {
                            list.innerHTML = '<table border="1" style="border-collapse: collapse; width: 100%;">' +
                                '<tr><th>IP Address</th><th>Device Name</th><th>Parser</th><th>Status</th><th>Created</th></tr>' +
                                devices.map(d => 
                                    `<tr>
                                        <td>${d.device_ip}</td>
                                        <td>${d.device_name}</td>
                                        <td>${d.parser_type}</td>
                                        <td>${d.enabled ? 'Enabled' : 'Disabled'}</td>
                                        <td>${d.created_at}</td>
                                    </tr>`
                                ).join('') +
                                '</table>';
                        }
                    })
                    .catch(err => console.error('Error loading devices:', err));
            </script>
        </body>
        </html>
        """
        return html_form
    
    elif request.method == 'POST':
        # Process form submission
        try:
            device_ip = request.form.get('device_ip', '').strip()
            device_name = request.form.get('device_name', '').strip()
            parser_type = request.form.get('parser_type', '').strip()
            
            # Validate inputs
            if not all([device_ip, device_name, parser_type]):
                return jsonify({'error': 'All fields are required'}), 400
            
            # Insert into ClickHouse
            query = f"""
            INSERT INTO network_logs.registered_devices 
            (device_ip, device_name, parser_type, created_at, updated_at, enabled) 
            VALUES ('{device_ip}', '{device_name}', '{parser_type}', now(), now(), 1)
            """
            
            clickhouse_query(query)
            
            # Notify syslog service to reload devices (TODO: implement)
            try:
                requests.post('http://localhost:5514/reload-devices', timeout=2)
            except:
                pass  # Service might not support this yet
            
            return jsonify({
                'success': True, 
                'message': f'Device {device_name} ({device_ip}) registered successfully'
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get list of registered devices"""
    try:
        query = "SELECT device_ip, device_name, parser_type, created_at, enabled FROM network_logs.registered_devices ORDER BY created_at DESC FORMAT JSONEachRow"
        result = clickhouse_query(query)
        
        devices = []
        if result:
            for line in result.split('\n'):
                if line.strip():
                    devices.append(json.loads(line))
        
        return jsonify(devices)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_ip>', methods=['DELETE'])
def delete_device(device_ip):
    """Delete a registered device"""
    try:
        query = f"ALTER TABLE network_logs.registered_devices DELETE WHERE device_ip = '{device_ip}'"
        clickhouse_query(query)
        return jsonify({'success': True, 'message': 'Device deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    print("Starting Device Manager API on http://0.0.0.0:8001")
    print("Access: http://10.12.50.61:8001/logs-sources/add/")
    app.run(host='0.0.0.0', port=8001, debug=True)