#!/bin/bash
# safe-firewall-drop
# Wraps the default Wazuh firewall-drop to add safety checks for Cloudflare & Crawlers.
# Must be placed in /var/ossec/active-response/bin/ and configured in ossec.conf

# Read the AR JSON payload from stdin
read INPUT_JSON

# Extract the IP address
IP=$(echo "$INPUT_JSON" | grep -oP '"srcip":"\K[^"]+')
if [ -z "$IP" ]; then
    # Pass through if no IP is found
    echo "$INPUT_JSON" | /var/ossec/active-response/bin/firewall-drop
    exit 0
fi

# 1. Cloudflare Check
CLOUDFLARE_IPS="/var/ossec/etc/lists/cloudflare_ips.txt"

# If Cloudflare list is older than 24 hours, update it
if [ ! -f "$CLOUDFLARE_IPS" ] || test `find "$CLOUDFLARE_IPS" -mtime +1`; then
    curl -s https://www.cloudflare.com/ips-v4 > "$CLOUDFLARE_IPS"
    curl -s https://www.cloudflare.com/ips-v6 >> "$CLOUDFLARE_IPS"
fi

# Use Python to accurately check if IP belongs to any of the Cloudflare CIDRs
python3 -c "
import sys, ipaddress
try:
    ip = ipaddress.ip_address(sys.argv[1])
    with open(sys.argv[2], 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                if ip in ipaddress.ip_network(line):
                    sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
" "$IP" "$CLOUDFLARE_IPS"

if [ $? -eq 0 ]; then
    # Cloudflare IP detected - do not block
    echo "$(date '+%Y-%m-%d %H:%M:%S') safe-firewall-drop: Ignored Cloudflare IP $IP" >> /var/ossec/logs/active-responses.log
    exit 0
fi

# 2. Crawler Check via Reverse DNS
# Get PTR record
PTR=$(dig +short -x "$IP" | head -n 1 | sed 's/\.$//')

if [ -n "$PTR" ]; then
    IS_CRAWLER=0
    # Match against official verified crawler domains
    if [[ "$PTR" =~ \.googlebot\.com$ || "$PTR" =~ \.google\.com$ || \
          "$PTR" =~ \.search\.msn\.com$ || \
          "$PTR" =~ \.yandex\.com$ || "$PTR" =~ \.yandex\.ru$ || \
          "$PTR" =~ \.baidu\.com$ || "$PTR" =~ \.baidu\.jp$ ]]; then
        
        # Verify Forward DNS matches original IP (Anti-Spoofing check)
        FORWARD_IP=$(dig +short "$PTR" | head -n 1)
        if [ "$FORWARD_IP" == "$IP" ]; then
            IS_CRAWLER=1
        fi
    fi

    if [ $IS_CRAWLER -eq 1 ]; then
        # Verified Crawler - do not block
        echo "$(date '+%Y-%m-%d %H:%M:%S') safe-firewall-drop: Ignored Verified Crawler ($PTR) IP $IP" >> /var/ossec/logs/active-responses.log
        exit 0
    fi
fi

# 3. Otherwise, block the IP
echo "$INPUT_JSON" | /var/ossec/active-response/bin/firewall-drop
