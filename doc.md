source env/bin/activate

python manage.py runserver 0.0.0.0:8000




sudo systemctl daemon-reload
sudo systemctl enable fortigate_to_clickhouse.service
sudo systemctl start fortigate_to_clickhouse.service
sudo systemctl status fortigate_to_clickhouse.service




sudo tcpdump -i any -A -n 'port 514' -c 5


curl 'http://localhost:9200/_cat/indices?v'


sudo lsof /var/log/syslog

clickhouse-client

USE network_logs;
DESCRIBE TABLE fortigate_traffic


net@edl:~$ sudo nano /etc/logstash/conf.d/fortigate.conf
net@edl:~$ sudo systemctl restart logstash


net@edl:~$ sudo cat /etc/systemd/system/fortigate_to_clickhouse.service
[sudo] password for net:
[Unit]
Description=Fortigate to ClickHouse Log Ingestor
After=network.target

[Service]
Type=simple
User=net
WorkingDirectory=/home/net/analyzer/scripts
ExecStart=/home/net/analyzer/env/bin/python /home/net/analyzer/scripts/fortigate_to_clickhouse.py
Restart=always
RestartSec=5
Environment=CH_HOST=localhost
Environment=CH_PORT=9000
Environment=CH_USER=default
Environment=CH_PASSWORD=Read@123
Environment=CH_DB=network_logs
# Optionally ensure venv bin is first in PATH:
Environment=PATH=/home/net/analyzer/env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target


