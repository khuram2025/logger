#!/bin/bash
# Script to set up port redirection from 514 to 5514 for syslog

# Enable port forwarding
echo "Enabling port forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

# Redirect UDP port 514 to 5514
echo "Setting up UDP port redirection (514 -> 5514)..."
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 5514

# Also redirect TCP if needed (some syslog implementations use TCP)
echo "Setting up TCP port redirection (514 -> 5514)..."
sudo iptables -t nat -A PREROUTING -p tcp --dport 514 -j REDIRECT --to-port 5514

# Save iptables rules (Ubuntu/Debian)
echo "Saving iptables rules..."
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Show current NAT rules
echo -e "\nCurrent NAT rules:"
sudo iptables -t nat -L -n -v

echo -e "\nPort redirection setup complete!"
echo "Syslog traffic on port 514 will be redirected to port 5514"