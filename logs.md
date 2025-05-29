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


echo -e "\n-- Current FortiGate Log File --"; stat /var/log/fortigate.log; echo -e "\n-- Rotated Log Files --"; ls -lh /var/log/fortigate.log* | sort -V


tail -n 5 /var/log/fortigate.log

tail -n 5 /var/log/paloalto-1004.log

