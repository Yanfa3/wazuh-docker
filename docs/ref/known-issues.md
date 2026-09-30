# Known Issues & Operational Notes

This document tracks known issues, quirks, and pending changes that require
investigation or validation before being applied to production systems.

---

## Agent Active Response: Hostname Instead of Raw IP Logged by sshd

**Status:** Pending — not yet applied to production  
**Affected Agent:** Agent 002 — `yanfaa.com` (CentOS 7)  
**Discovered:** 2026-09-30  

### Symptom

Wazuh rule `5503` (PAM: User login failed, T1110.001 — Password Guessing) fired
**3 times in 10 minutes** from the same attacker IP `160.251.202.248` on Agent 002.
The attacker was never blocked. The `Source IP` in the Slack alert showed a hostname
instead of a raw IP:

```
Source IP: v160-251-202-248.1prz.static.cnode.jp
```

Meanwhile, the same IP attacking Agent 005 (Ubuntu 22.04) was blocked immediately
and appeared as a raw IP:

```
Source IP: 160.251.202.248
```

### Root Cause

CentOS 7's OpenSSH RPM package is **compiled with `UseDNS yes` as the built-in
default**. When `UseDNS` is commented out in `sshd_config` (as is the case on all
servers), each server falls back to its own compile-time default:

| Agent | OS | OpenSSH | Compile-time `UseDNS` default | Logs |
|-------|----|---------|-------------------------------|------|
| 002 — yanfaa.com | CentOS 7 | 9.8p1 | `yes` (RHEL/CentOS RPM patch) | Hostname |
| 005 — yanfaa-community | Ubuntu 22.04 | 9.8p1 | `no` (Debian default) | Raw IP |

When `sshd` does a reverse DNS lookup and logs the hostname, the value passed to
the Wazuh `firewall-drop` active response script is a hostname string, not a valid
IP address. The `firewall-drop` script validates the `srcip` field as an IP address
before calling `iptables` — if it receives a hostname, it **exits silently without
blocking**.

This is why the same attacker was able to trigger 3 alerts in 10 minutes on Agent
002 and never got blocked.

### Proposed Fix

On Agent 002 (CentOS 7), explicitly set `UseDNS no` in `sshd_config` to override
the compile-time default:

```bash
# 1. Edit /etc/ssh/sshd_config
#    Change:  #UseDNS yes
#    To:       UseDNS no
sudo sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config

# 2. Verify
grep -i "UseDNS" /etc/ssh/sshd_config
# Expected output:
# UseDNS no

# 3. Validate sshd config syntax before restarting
sudo sshd -t

# 4. Apply
sudo systemctl restart sshd
```

### Why `UseDNS no` Is Safe

- `UseDNS yes` was historically used for an extra authentication check
  (forward-confirmed reverse DNS), but this provides **no real security benefit**
  and is considered obsolete for this purpose.
- Setting `UseDNS no` **speeds up SSH connections** by removing the DNS lookup
  on every connection attempt.
- It **prevents DNS spoofing** from influencing your audit logs.
- This is the default on all modern Ubuntu/Debian systems.
- OpenSSH's own upstream changed the default to `no` in version 6.8 (2015).

### Why This Is Not Applied Yet

Changing `sshd_config` and restarting `sshd` on a production server carries a risk
of locking yourself out if the config is malformed. The `sudo sshd -t` validation
step mitigates this, but a maintenance window and a second open SSH session are
recommended before applying on a live server.

### Verification After Fix

After applying the fix, confirm the next brute-force attempt is blocked correctly:

```bash
# Watch active response log in real time
sudo tail -f /var/ossec/logs/active-responses.log

# Confirm attacker IP appears in iptables DROP
sudo iptables -L INPUT -n | grep DROP
```

The Slack alert `Source IP` field should show a raw IP address (e.g., `160.251.202.248`)
instead of a hostname, and only **one** alert should fire per attacker — not multiple
repeated alerts.

### Also Manually Block the Current Attacker

The IP `160.251.202.248` is not in iptables on Agent 002 because the block failed.
Block it manually until the fix is applied:

```bash
sudo iptables -I INPUT -s 160.251.202.248 -j DROP
```

---
