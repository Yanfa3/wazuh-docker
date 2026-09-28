#!/bin/bash

# Path to the Nginx configuration file for Cloudflare IPs
NGINX_CONF_PATH="/etc/nginx/conf.d/cloudflare.conf"

echo "# Cloudflare IPs" > $NGINX_CONF_PATH
echo "# Updated on $(date)" >> $NGINX_CONF_PATH

# Fetch IPv4
curl -s https://www.cloudflare.com/ips-v4 | while read ip; do
    echo "set_real_ip_from $ip;" >> $NGINX_CONF_PATH
done

# Fetch IPv6
curl -s https://www.cloudflare.com/ips-v6 | while read ip; do
    echo "set_real_ip_from $ip;" >> $NGINX_CONF_PATH
done

echo "real_ip_header CF-Connecting-IP;" >> $NGINX_CONF_PATH

# Test Nginx config and reload
nginx -t && systemctl reload nginx
