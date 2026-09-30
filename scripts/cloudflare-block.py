#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error
import os
import ipaddress
from datetime import datetime

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
SAFE_IPS_RAW = env_config.get("SAFE_IPS", "127.0.0.1")
SAFE_IPS = [ip.strip() for ip in SAFE_IPS_RAW.split(",") if ip.strip()]
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
        return {
            "text": f"Wazuh Active Response | Successfully {action.lower()}ed IP `{ip}` at Cloudflare."
        }

    rule = alert_data.get("rule", {})
    agent = alert_data.get("agent", {})
    manager = alert_data.get("manager", {})
    mitre = rule.get("mitre", {})

    rule_id = str(rule.get("id", "-"))
    level = rule.get("level", "-")
    description = rule.get("description", "Unknown detection")

    mitre_ids = mitre.get("id", [])
    mitre_tactics = mitre.get("tactic", [])
    mitre_techniques = mitre.get("technique", [])

    agent_id = agent.get("id", "-")
    agent_name = agent.get("name", "-")
    agent_ip = agent.get("ip", "-")

    location = alert_data.get("location", "-")
    timestamp = alert_data.get("timestamp", "-")
    alert_id = alert_data.get("id", "-")
    manager_name = manager.get("name", "-")

    if action == "ADD":
        action_text = "🔴 BLOCKED AT EDGE WAF"
        title = "🚨 WAZUH SECURITY ALERT — CLOUDFLARE IP BLOCKED"
    elif action == "DELETE":
        action_text = "🟢 UNBLOCKED AT EDGE WAF"
        title = "🔓 WAZUH SECURITY ALERT — CLOUDFLARE IP UNBLOCKED"
    else:
        action_text = action.upper()
        title = "⚠️ WAZUH SECURITY ALERT — CLOUDFLARE"

    block_type = "Temporary (Cloudflare)" if action == "ADD" else "Temporary — timeout expired"

    if "ssh" in description.lower():
        attack_type = "SSH / Authentication Attack"
    elif "web server" in description.lower() or "400" in description.lower() or "nginx" in description.lower():
        attack_type = "Web Server Attack"
    elif "shellshock" in description.lower():
        attack_type = "Shellshock Attack"
    elif "crc-32" in description.lower():
        attack_type = "SSH CRC-32 Attack"
    elif "pam" in description.lower() or "login" in description.lower():
        attack_type = "PAM / Authentication Attack"
    else:
        attack_type = "Security Detection"

    fields = [
        {
            "title": "Action",
            "value": f"*{action_text}*",
            "short": True,
        },
        {
            "title": "Block Type",
            "value": block_type,
            "short": True,
        },
        {
            "title": "Source IP",
            "value": f"*`{ip}`*",
            "short": True,
        },
        {
            "title": "Attack Type",
            "value": attack_type,
            "short": True,
        },
        {
            "title": "Rule",
            "value": f"`{rule_id}` — Level {level}",
            "short": True,
        },
        {
            "title": "Detection",
            "value": description,
            "short": False,
        },
    ]

    frequency = rule.get("frequency")
    timeframe = rule.get("timeframe")
    if frequency:
        detection_window = f"{frequency} events"
        if timeframe:
            detection_window += f" within {timeframe} seconds"
        fields.append({
            "title": "Detection Threshold",
            "value": detection_window,
            "short": True,
        })

    if mitre_ids:
        if isinstance(mitre_ids, list):
            mitre_text = ", ".join(str(x) for x in mitre_ids)
        else:
            mitre_text = str(mitre_ids)

        if mitre_techniques:
            if isinstance(mitre_techniques, list):
                mitre_text += " — " + ", ".join(str(x) for x in mitre_techniques)
            else:
                mitre_text += " — " + str(mitre_techniques)

        fields.append({
            "title": "MITRE ATT&CK",
            "value": mitre_text,
            "short": True,
        })

    if mitre_tactics:
        if isinstance(mitre_tactics, list):
            tactic_text = ", ".join(str(x) for x in mitre_tactics)
        else:
            tactic_text = str(mitre_tactics)

        fields.append({
            "title": "MITRE Tactic",
            "value": tactic_text,
            "short": True,
        })

    fields.extend([
        {
            "title": "Agent",
            "value": f"`{agent_id}` — {agent_name}",
            "short": True,
        },
        {
            "title": "Agent IP",
            "value": f"`{agent_ip}`",
            "short": True,
        },
        {
            "title": "Log Source",
            "value": location,
            "short": True,
        },
        {
            "title": "Time",
            "value": timestamp,
            "short": True,
        },
        {
            "title": "Active Response",
            "value": f"`cloudflare-block` — `{action.upper()}`",
            "short": True,
        },
        {
            "title": "Alert ID",
            "value": f"`{alert_id}`",
            "short": True,
        },
        {
            "title": "Manager",
            "value": f"`{manager_name}`",
            "short": True,
        },
    ])

    return {
        "text": title,
        "attachments": [
            {
                "color": "#d32f2f" if action == "ADD" else "#2e7d32",
                "fields": fields,
                "footer": "Wazuh Active Response",
                "ts": int(datetime.now().timestamp()),
            }
        ],
    }

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

def is_safe_ip(ip_str):
    if not ip_str:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for safe in SAFE_IPS:
            try:
                if ip_obj in ipaddress.ip_network(safe, strict=False):
                    return True
            except ValueError:
                # Fallback if network parsing fails
                if ip_str == safe:
                    return True
    except ValueError:
        pass
    return False

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
            
        # Ignore safe IPs or missing IPs
        if is_safe_ip(srcip):
            log(f"Ignoring action for safe/missing IP: {srcip}")
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
