#!/bin/bash
# update-nginx-cloudflare.sh
# Automates updating Cloudflare IP ranges in Nginx to securely restore the real visitor IP.

NGINX_CONF="/etc/nginx/conf.d/cloudflare.conf"

echo "# Cloudflare IP Ranges (Auto-Updated)" > "$NGINX_CONF"
echo "# Required to securely restore CF-Connecting-IP" >> "$NGINX_CONF"
echo "" >> "$NGINX_CONF"

# Fetch IPv4 and IPv6 directly from Cloudflare and format as Nginx directives
curl -s https://www.cloudflare.com/ips-v4 | sed -e 's/^/set_real_ip_from /' -e 's/$/;/' >> "$NGINX_CONF"
curl -s https://www.cloudflare.com/ips-v6 | sed -e 's/^/set_real_ip_from /' -e 's/$/;/' >> "$NGINX_CONF"

echo "" >> "$NGINX_CONF"
# Trust CF-Connecting-IP as the true visitor IP
echo "real_ip_header CF-Connecting-IP;" >> "$NGINX_CONF"

# Test and reload Nginx if valid
if nginx -t > /dev/null 2>&1; then
    echo "Nginx configuration tested successfully. Reloading..."
    systemctl reload nginx || service nginx reload
else
    echo "Error: Nginx configuration test failed!"
    exit 1
fi
