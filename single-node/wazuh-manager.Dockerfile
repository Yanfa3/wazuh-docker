FROM wazuh/wazuh-manager:4.14.7

# ── Active Response Scripts ──────────────────────────────────────────────────

# Cloudflare edge WAF block (used by rules: 31151, 31152, 31153, 31154)
COPY ./scripts/cloudflare-block.py /var/ossec/active-response/bin/cloudflare-block

# Safe firewall drop — wraps firewall-drop with Cloudflare IP & crawler checks
# (used by rules: 5712, 5503, 5720, 5763)
COPY ./scripts/safe-firewall-drop.sh /var/ossec/active-response/bin/safe-firewall-drop

# Set strict permissions required by Wazuh for Active Response scripts
RUN chmod 750 /var/ossec/active-response/bin/cloudflare-block \
              /var/ossec/active-response/bin/safe-firewall-drop && \
    chown root:wazuh /var/ossec/active-response/bin/cloudflare-block \
                     /var/ossec/active-response/bin/safe-firewall-drop

# ── Integration Scripts ──────────────────────────────────────────────────────

# Slack alert integration (triggered by AR notification rules 651, 652)
COPY ./scripts/custom-wazuh-slack /var/ossec/integrations/custom-wazuh-slack

# Set strict permissions required by Wazuh for integration scripts
RUN chmod 750 /var/ossec/integrations/custom-wazuh-slack && \
    chown root:wazuh /var/ossec/integrations/custom-wazuh-slack
