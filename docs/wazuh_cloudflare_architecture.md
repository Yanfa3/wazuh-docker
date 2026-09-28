# Wazuh & Cloudflare Security Architecture

## Overview
This document summarizes the architectural changes made to the Wazuh deployment to correctly handle web traffic proxied through Cloudflare. The previous architecture relied on local `iptables` (`firewall-drop`), which is ineffective against proxied web traffic and caused legitimate Cloudflare edge servers to be inadvertently banned.

The new architecture drops attackers directly at the **Cloudflare Edge (WAF)**, restores real client IPs in Nginx, and fully automates the deployment process via a GitOps pipeline.

---

## 1. Nginx Real-IP Restoration
* **The Problem**: Nginx was logging Cloudflare's proxy IP addresses instead of the attacker's real IP. This caused Wazuh to trigger active responses against Cloudflare itself.
* **The Solution**: Created `scripts/update-cloudflare-ips.sh`. This script dynamically fetches the latest Cloudflare IPv4 and IPv6 subnets and generates an Nginx configuration (`/etc/nginx/conf.d/cloudflare.conf`) utilizing the `set_real_ip_from` and `real_ip_header CF-Connecting-IP` directives.
* **Automation**: Configured a weekly cron job (`0 2 * * 1`) on the web server to run this script every Monday at 2:00 AM, ensuring Nginx always trusts the most up-to-date Cloudflare subnets.

## 2. Cloudflare Active Response (WAF API)
* **The Problem**: Even with the real IP identified, executing local `iptables` drops on the server cannot block web requests, because the incoming network packets originate from Cloudflare's servers, not the attacker's IP.
* **The Solution**: Developed `scripts/cloudflare-block.py`. When Wazuh detects a web attack, this script is triggered. It parses the JSON alert and makes an authenticated API call to the Cloudflare WAF to ban the attacker's IP globally across the CDN.
* **Security**: API credentials (`CF_API_TOKEN` and `CF_ACCOUNT_ID`) are securely read from an uncommitted `.env.local` file, ensuring secrets never leak into version control.

## 3. Wazuh Configuration (`wazuh_manager.conf`)
* **Whitelist Fix**: Consolidated duplicate `<global>` XML blocks that were causing parsing errors. Added all Cloudflare CIDR blocks to the global `<white_list>` so Wazuh natively ignores alerts originating from Cloudflare infrastructure.
* **Active Response Routing**: 
  - Registered the new `<command>` for `cloudflare-block`.
  - Modified Web/Nginx attack rules (`31151`, `31152`, `31153`, `31154`) to trigger the Cloudflare block.
* **Defense-in-Depth**: Retained the original `firewall-drop` active response for the web rules. This ensures that if a web attacker later attempts a direct attack on a non-proxied port (e.g., SSH on Port 22), they are still dropped by the local firewall.

## 4. GitOps Deployment Automation
* **The Problem**: Injecting custom scripts and configurations into the Wazuh Docker container previously required manual `docker cp` commands, leading to configuration drift and deployment errors.
* **The Solution**: 
  1. **Custom Dockerfile**: Created `single-node/wazuh-manager.Dockerfile` to automatically copy the Python script into the image and strictly enforce Wazuh's required `root:wazuh` ownership and `750` permissions during the build.
  2. **Docker Compose**: Updated `docker-compose.yml` to build the custom image (`build: .`) and bind-mount `.env.local` read-only.
  3. **Config Templating**: Modified `scripts/deploy.sh` to compile `ossec.conf` dynamically. It injects the `SLACK_WEBHOOK_URL` from `.env.local` into the Git configuration template (`wazuh_manager.conf`) using `envsubst` before syncing it to the production secrets folder (`/opt/wazuh-secrets/`).

This fully automated pipeline ensures that pushing to the `master` branch results in a perfect, zero-touch deployment of the entire security architecture.
