FROM wazuh/wazuh-manager:4.14.7

# Copy the custom Cloudflare Active Response script
COPY ./scripts/cloudflare-block.py /var/ossec/active-response/bin/cloudflare-block

# Set strict permissions required by Wazuh for Active Response scripts
RUN chmod 750 /var/ossec/active-response/bin/cloudflare-block && \
    chown root:wazuh /var/ossec/active-response/bin/cloudflare-block
