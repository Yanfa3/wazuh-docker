#!/usr/bin/env python3
import sys
import json
import requests

import os

# ==========================================
# CONFIGURATION
# ==========================================
# We read from a .env.local file mounted or copied into the container
ENV_FILE = "/var/ossec/active-response/bin/.env.local"

def load_env(filepath):
    env_vars = {}
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    # Strip quotes if they exist
                    env_vars[key.strip()] = value.strip().strip('"\'')
    return env_vars

env_config = load_env(ENV_FILE)

CF_API_TOKEN = env_config.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = env_config.get("CF_ACCOUNT_ID", "")
SLACK_WEBHOOK_URL = env_config.get("SLACK_WEBHOOK_URL", "")
# ==========================================

LOG_FILE = "/var/ossec/logs/active-responses.log"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"cloudflare-block.py: {msg}\n")

def send_slack(msg):
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": msg}, timeout=5)
        except Exception as e:
            log(f"Failed to send Slack alert: {e}")

def block_ip(ip):
    # Cloudflare IP Access Rules API (Account level)
    # Reference: https://developers.cloudflare.com/api/operations/ip-access-rules-for-an-account-create-an-ip-access-rule
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/firewall/access_rules/rules"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "mode": "block",
        "configuration": {
            "target": "ip",
            "value": ip
        },
        "notes": "Blocked automatically by Wazuh Active Response"
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        data = response.json()
        
        if response.status_code == 200 and data.get("success"):
            log(f"Successfully blocked IP {ip} at Cloudflare.")
            send_slack(f"✅ *Wazuh Active Response* | Successfully blocked IP `{ip}` at Cloudflare.")
            
        elif response.status_code == 400 and "already exists" in str(data.get("errors")):
            log(f"IP {ip} is already blocked at Cloudflare.")
            # We don't send a Slack alert here to avoid spamming for duplicates
            
        else:
            err = data.get("errors", response.text)
            log(f"Failed to block IP {ip} at Cloudflare. Error: {err}")
            send_slack(f"❌ *Wazuh Active Response* | Failed to block IP `{ip}` at Cloudflare. Error: {err}")
            
    except Exception as e:
        log(f"Exception while calling Cloudflare API: {e}")
        send_slack(f"❌ *Wazuh Active Response* | Exception while calling Cloudflare API for `{ip}`: {e}")

def main():
    # Wazuh >= 4.2 passes arguments as a JSON string via stdin
    input_str = sys.stdin.readline()
    if not input_str:
        return
        
    try:
        alert = json.loads(input_str)
        command = alert.get("command")
        
        # We only handle 'add' commands (blocks). 
        # For 'delete' (unbans), you would call the Cloudflare DELETE API endpoint.
        if command != "add":
            return
            
        parameters = alert.get("parameters", {})
        alert_data = parameters.get("alert", {})
        
        # Try to extract the source IP from the alert
        srcip = None
        data_obj = alert_data.get("data", {})
        
        if "srcip" in data_obj:
            srcip = data_obj["srcip"]
        elif "srcip" in alert_data:
            srcip = alert_data["srcip"]
            
        # Ignore localhost or missing IPs
        if not srcip or srcip == "127.0.0.1":
            return
            
        log(f"Triggered Cloudflare block for {srcip}")
        block_ip(srcip)
        
    except json.JSONDecodeError:
        log("Error parsing JSON input from Wazuh.")
    except Exception as e:
        log(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
