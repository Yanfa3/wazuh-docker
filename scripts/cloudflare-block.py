#!/usr/bin/env python3
import sys
import json
import urllib.request
import urllib.error
import urllib.parse
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
TEMPORARY_NOTES_PREFIX = "Wazuh temporary 31151: "
PERMANENT_NOTES = "Blocked automatically by Wazuh Active Response"

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

def build_slack_payload(alert_data, action, ip, temporary=False):
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

    block_type = (
        "Temporary — native repeat-offender timeout"
        if temporary and action == "ADD"
        else "Temporary — response reverted" if temporary else "Permanent"
    )

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

def api_request(method, path="", payload=None):
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/firewall/access_rules/rules{path}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        # Do not log URLs, headers, or credentials.
        raise RuntimeError(f"Cloudflare HTTP {exc.code}") from None
    if not data.get("success"):
        raise RuntimeError(f"Cloudflare rejected {method}: {data.get('errors', [])}")
    return data


def matching_rules(ip):
    query = urllib.parse.urlencode({
        "mode": "block", "configuration.target": ip_target(ip),
        "configuration.value": ip, "per_page": 50,
    })
    data = api_request("GET", "?" + query)
    if data.get("result_info", {}).get("total_pages", 1) > 1:
        raise RuntimeError("Ambiguous Cloudflare rule lookup; refusing mutation")
    # Verify exact matches locally as well as applying API filters.
    return [rule for rule in data.get("result", [])
            if rule.get("mode") == "block"
            and rule.get("configuration") == {"target": ip_target(ip), "value": ip}]


def ip_target(ip):
    return "ip6" if ipaddress.ip_address(ip).version == 6 else "ip"


def temporary_notes(alert_data):
    # Each timeout may remove only its own response, never a newer ban.
    alert_id = alert_data.get("id")
    if not isinstance(alert_id, str) or not alert_id or len(alert_id) > 100:
        raise ValueError("Temporary response requires a valid alert ID")
    return TEMPORARY_NOTES_PREFIX + alert_id


def block_ip(ip, alert_data, temporary=False):
    notes = temporary_notes(alert_data) if temporary else PERMANENT_NOTES
    try:
        existing = matching_rules(ip)
        if existing:
            if not temporary:
                # A permanent detection supersedes any pending temporary expiry.
                for rule in existing:
                    if rule.get("notes", "").startswith(TEMPORARY_NOTES_PREFIX):
                        api_request("PATCH", "/" + rule["id"], {
                            "mode": "block", "notes": PERMANENT_NOTES,
                        })
                        log(f"Promoted IP {ip} to a permanent Cloudflare block.")
                        send_slack(build_slack_payload(alert_data, "ADD", ip))
            log(f"IP {ip} already blocked at Cloudflare; existing rules preserved.")
            return
        api_request("POST", payload={
            "mode": "block",
            "configuration": {"target": ip_target(ip), "value": ip},
            "notes": notes,
        })
        log(f"Successfully blocked IP {ip} at Cloudflare ({'temporary' if temporary else 'permanent'}).")
        send_slack(build_slack_payload(alert_data, "ADD", ip, temporary))
    except Exception as exc:
        log(f"Failed to block IP {ip} at Cloudflare: {exc}")
        send_slack(f"Cloudflare block failed for `{ip}`: {exc}")
        raise


def unblock_ip(ip, alert_data):
    try:
        notes = temporary_notes(alert_data)
        owned = [rule for rule in matching_rules(ip) if rule.get("notes") == notes]
        if not owned:
            log(f"No owned temporary Cloudflare block for {ip}; existing rules preserved.")
            return
        for rule in owned:
            api_request("DELETE", "/" + rule["id"])
        log(f"Successfully removed temporary Cloudflare block for IP {ip}.")
        send_slack(build_slack_payload(alert_data, "DELETE", ip, temporary=True))
    except Exception as exc:
        log(f"Failed to remove temporary Cloudflare block for {ip}: {exc}")
        send_slack(f"Cloudflare unblock failed for `{ip}`; block may remain: {exc}")
        raise


def check_keys(ip):
    # STDOUT is reserved for the newline-delimited Wazuh control protocol.
    print(json.dumps({
        "version": 1,
        "origin": {"name": "cloudflare-block", "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": [ip]},
    }), flush=True)
    response = json.loads(sys.stdin.readline())
    if response.get("command") == "abort":
        return False
    if response.get("command") != "continue":
        raise ValueError("Unexpected Wazuh check_keys response")
    return True


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
        return True
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
            
        temporary = "--temporary" in parameters.get("extra_args", [])
        if command == "delete" and not temporary:
            log("Ignoring delete for permanent Cloudflare command")
            return

        # Ignore safe IPs or missing IPs
        if is_safe_ip(srcip):
            log(f"Ignoring action for safe/missing IP: {srcip}")
            return
            
        if temporary:
            temporary_notes(alert_data)
        if command == "add":
            if temporary and not check_keys(srcip):
                return
            log(f"Triggered Cloudflare block for {srcip}")
            block_ip(srcip, alert_data, temporary)
        elif command == "delete":
            log(f"Triggered Cloudflare unblock for {srcip}")
            unblock_ip(srcip, alert_data)
        
    except json.JSONDecodeError:
        log("Error parsing JSON input from Wazuh.")
        return 1
    except Exception as e:
        log(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main() or 0)
