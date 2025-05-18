source env/bin/activate

python manage.py runserver 0.0.0.0:8000




sudo systemctl daemon-reload
sudo systemctl enable fortigate_to_clickhouse.service
sudo systemctl start fortigate_to_clickhouse.service
sudo systemctl status fortigate_to_clickhouse.service




sudo tcpdump -i any -A -n 'port 514' -c 5


curl 'http://localhost:9200/_cat/indices?v'

tail -n 5 /var/log/fortigate.log

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




net@edl:/etc/rsyslog.d$ cat fortigate.conf
#### start fortigate.conf ####

# Load UDP syslog listener only once
module(load="imudp")

# Template for clean FortiGate messages (without PRI)
template(name="FortiGateRaw" type="string" string="%rawmsg-after-pri%\n")

# Log all messages coming from 192.168.100.221 only
if ($fromhost-ip == '192.168.100.221') then {
    action(
        type="omfile"
        file="/var/log/fortigate.log"
        template="FortiGateRaw"
    )
    stop
}

#### end fortigate.conf ####
net@edl:/etc/rsyslog.d$ ls
50-default.conf  60-fortigate.conf.bak  99-udp-test.conf.disabled  fortigate.conf  fortigate.conf.bak
net@edl:/etc/rsyslog.d$ cat 50-default.conf
#  Default log rules for rsyslog on Ubuntu:

# Log all the mail messages in one place.
mail.*            -/var/log/mail.log

# Emergencies are sent to everybody logged in.
*.emerg           :omusrmsg:*

if ($fromhost-ip != '192.168.100.221') then {
    *.info;mail.none;authpriv.none;cron.none    /var/log/syslog
}

# Authentication logs
auth,authpriv.*   /var/log/auth.log

# Cron logs
cron.*            /var/log/cron.log

# Kernel messages
kern.*            -/var/log/kern.log

# FTP logins
auth.*;mail.none  /var/log/auth.log

# News server
news.crit         /var/log/news/news.crit
news.err          /var/log/news/news.err
news.notice       /var/log/news/news.notice
