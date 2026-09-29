#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error
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

def send_slack(payload):
    if SLACK_WEBHOOK_URL:
        if isinstance(payload, str):
            payload = {"text": payload}
        try:
            req = urllib.request.Request(
                SLACK_WEBHOOK_URL, 
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            log(f"Failed to send Slack alert: {e}")

def build_slack_payload(alert_data, action, ip):
    if not alert_data:
        return f"Wazuh Active Response | Successfully {action.lower()}ed IP {ip} at Cloudflare."
        
    rule = alert_data.get("rule", {})
    agent = alert_data.get("agent", {})
    mitre = rule.get("mitre", {})
    
    rule_id = rule.get("id", "N/A")
    rule_level = rule.get("level", "N/A")
    rule_desc = rule.get("description", "N/A")
    
    mitre_ids = mitre.get("id", [""])
    mitre_techs = mitre.get("technique", [""])
    mitre_tactics = mitre.get("tactic", [""])
    mitre_attck = f"{mitre_ids[0]} — {mitre_techs[0]}" if mitre_ids and mitre_ids[0] else "N/A"
    mitre_tactic = mitre_tactics[0] if mitre_tactics and mitre_tactics[0] else "N/A"
    
    agent_id = agent.get("id", "N/A")
    agent_name = agent.get("name", "N/A")
    agent_ip = agent.get("ip", "N/A")
    
    log_source = alert_data.get("location", "N/A")
    timestamp = alert_data.get("timestamp", "N/A")
    alert_id = alert_data.get("id", "N/A")
    manager = alert_data.get("manager", {}).get("name", "N/A")
    
    if action == "ADD":
        title = "🚨 WAZUH SECURITY ALERT — CLOUDFLARE IP BLOCKED"
        action_text = "🔴 BLOCKED AT EDGE WAF"
    else:
        title = "♻️ WAZUH SECURITY ALERT — CLOUDFLARE IP UNBLOCKED"
        action_text = "🟢 UNBLOCKED AT EDGE WAF"
        
    text = (
        f"*{title}*\n"
        f"*Action* {action_text}\n"
        f"*Block Type* Temporary (Cloudflare)\n"
        f"*Source IP* `{ip}`\n"
        f"*Attack Type* Security Detection\n"
        f"*Rule* {rule_id} — Level {rule_level}\n"
        f"*Detection* {rule_desc}\n"
        f"*MITRE ATT&CK* {mitre_attck}\n"
        f"*MITRE Tactic* {mitre_tactic}\n"
        f"*Agent* {agent_id} — {agent_name}\n"
        f"*Agent IP* {agent_ip}\n"
        f"*Log Source* {log_source}\n"
        f"*Time* {timestamp}\n"
        f"*Active Response* cloudflare-block — {action}\n"
        f"*Alert ID* {alert_id}\n"
        f"*Manager* {manager}"
    )
    return {"text": text}

def block_ip(ip, alert_data):
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
        req = urllib.request.Request(
            url, 
            data=json.dumps(payload).encode('utf-8'), 
            headers=headers
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            if response.status == 200 and data.get("success"):
                log(f"Successfully blocked IP {ip} at Cloudflare.")
                send_slack(build_slack_payload(alert_data, "ADD", ip))
                
    except urllib.error.HTTPError as e:
        error_data = e.read().decode()
        try:
            data = json.loads(error_data)
            if e.code == 400 and ("already exists" in str(data.get("errors")) or "duplicate_of_existing" in str(data.get("errors"))):
                log(f"IP {ip} is already blocked at Cloudflare.")
                return
            err = data.get("errors", error_data)
        except json.JSONDecodeError:
            err = error_data
            
        log(f"Failed to block IP {ip} at Cloudflare. Error: {err}")
        send_slack(f"❌ *Wazuh Active Response* | Failed to block IP `{ip}` at Cloudflare. Error: {err}")
        
    except Exception as e:
        log(f"Exception while calling Cloudflare API: {e}")
        send_slack(f"❌ *Wazuh Active Response* | Exception while calling Cloudflare API for `{ip}`: {e}")

def unblock_ip(ip, alert_data):
    # Step 1: Find the Rule ID for this IP
    search_url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/firewall/access_rules/rules?mode=block&configuration.target=ip&configuration.value={ip}"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        req = urllib.request.Request(search_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            results = data.get("result", [])
            
            if not results:
                log(f"IP {ip} not found in Cloudflare blocklist. Nothing to unban.")
                return
                
            rule_id = results[0].get("id")
            
    except Exception as e:
        log(f"Failed to search Cloudflare API for IP {ip}: {e}")
        return
        
    # Step 2: Delete the Rule
    delete_url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/firewall/access_rules/rules/{rule_id}"
    try:
        req = urllib.request.Request(delete_url, headers=headers, method="DELETE")
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            if response.status == 200 and data.get("success"):
                log(f"Successfully unblocked IP {ip} at Cloudflare.")
                send_slack(build_slack_payload(alert_data, "DELETE", ip))
    except urllib.error.HTTPError as e:
        error_data = e.read().decode()
        log(f"Failed to delete Cloudflare rule for IP {ip}. Error: {error_data}")
        send_slack(f"❌ *Wazuh Active Response* | Failed to unblock IP `{ip}` at Cloudflare. Error: {error_data}")
    except Exception as e:
        log(f"Exception while calling Cloudflare DELETE API for {ip}: {e}")
        send_slack(f"❌ *Wazuh Active Response* | Exception while deleting Cloudflare rule for `{ip}`: {e}")

def main():
    # Wazuh >= 4.2 passes arguments as a JSON string via stdin
    input_str = sys.stdin.readline()
    if not input_str:
        return
        
    try:
        alert = json.loads(input_str)
        command = alert.get("command")
        
        if command not in ["add", "delete"]:
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
            
        if command == "add":
            log(f"Triggered Cloudflare block for {srcip}")
            block_ip(srcip, alert_data)
        elif command == "delete":
            log(f"Triggered Cloudflare unblock for {srcip}")
            unblock_ip(srcip, alert_data)
        
    except json.JSONDecodeError:
        log("Error parsing JSON input from Wazuh.")
    except Exception as e:
        log(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
