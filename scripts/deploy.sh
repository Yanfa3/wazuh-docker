#!/bin/bash
# =============================================================================
# Yanfaa Wazuh Deployment Script
# Called by GitHub Actions CI/CD via AWS SSM on every push to master.
#
# Logic:
#   1. Pull latest code from git
#   2. Validate SSL cert health (all files present + chain verified + not expired)
#   3. If certs are invalid/missing -> regenerate + full restart (all services)
#   4. If certs are healthy -> pull images + restart wazuh.manager only
# =============================================================================
set -euo pipefail

WAZUH_DIR="/home/yanfaa/wazuh-docker"
SINGLE_NODE_DIR="$WAZUH_DIR/single-node"
CERT_DIR="$SINGLE_NODE_DIR/config/wazuh_indexer_ssl_certs"
COMPOSE_OPTS="--env-file $WAZUH_DIR/.env --env-file $WAZUH_DIR/.env.local"

cd "$SINGLE_NODE_DIR"

# -----------------------------------------------------------------------------
# 2. Validate SSL certificate health
# -----------------------------------------------------------------------------
echo "==> [1/3] Validating SSL certificates..."
CERTS_VALID=true

# Check all required cert files exist
REQUIRED_CERTS=(
  "root-ca.pem"
  "root-ca.key"
  "wazuh.indexer.pem"
  "wazuh.indexer-key.pem"
  "wazuh.dashboard.pem"
  "wazuh.dashboard-key.pem"
  "admin.pem"
  "admin-key.pem"
)

for cert_file in "${REQUIRED_CERTS[@]}"; do
  if [ ! -f "$CERT_DIR/$cert_file" ]; then
    echo "    x MISSING: $cert_file"
    CERTS_VALID=false
    break
  fi
done

# Verify cert chain: all service certs must be signed by the same root-ca.pem
if [ "$CERTS_VALID" = "true" ]; then
  for cert in "wazuh.indexer.pem" "wazuh.dashboard.pem" "admin.pem"; do
    if ! openssl verify -CAfile "$CERT_DIR/root-ca.pem" "$CERT_DIR/$cert" > /dev/null 2>&1; then
      echo "    x INVALID chain: $cert is not signed by root-ca.pem (cert mismatch)"
      CERTS_VALID=false
      break
    fi
  done
fi

# Verify certs are not expired or expiring within 24 hours
if [ "$CERTS_VALID" = "true" ]; then
  for cert in "wazuh.indexer.pem" "wazuh.dashboard.pem"; do
    if ! openssl x509 -checkend 86400 -noout -in "$CERT_DIR/$cert" > /dev/null 2>&1; then
      echo "    x EXPIRING/EXPIRED: $cert expires within 24 hours"
      CERTS_VALID=false
      break
    fi
  done
fi

# -----------------------------------------------------------------------------
# 3. Regenerate certs if invalid (triggers full restart of all services)
# -----------------------------------------------------------------------------
FULL_RESTART=false

if [ "$CERTS_VALID" = "false" ]; then
  echo "    Certificates are invalid or missing. Regenerating from scratch..."
  rm -rf "$CERT_DIR"
  docker compose -f generate-indexer-certs.yml run --rm generator
  chmod 755 "$CERT_DIR"
  echo "    Certificates regenerated successfully"
  FULL_RESTART=true
else
  echo "    All certificates are healthy"
fi

# -----------------------------------------------------------------------------
# 3.5. Ensure API Password is synchronized
# -----------------------------------------------------------------------------
echo "==> Checking API password synchronization..."
# We test if the manager's internal rbac.db matches the .env.local API_PASSWORD.
# If it returns 401 Unauthorized, we safely delete rbac.db. The manager will
# automatically recreate it on restart using the environment variables!
# Read a single KEY from .env.local by exact name (like python dict lookup):
#   - anchored to line start, optional 'export ' prefix
#   - strips CR (CRLF files), surrounding quotes and whitespace
#   - if the key is duplicated, the last definition wins (always ONE line)
get_env() {
  local key="$1" file="$WAZUH_DIR/.env.local"
  [ -f "$file" ] || return 0
  grep -E "^[[:space:]]*(export[[:space:]]+)?${key}=" "$file" \
    | tail -n 1 \
    | sed -E "s/^[[:space:]]*(export[[:space:]]+)?${key}=//; s/\r$//; s/^[[:space:]]+|[[:space:]]+$//g; s/^[\"'](.*)[\"']$/\1/" \
    || true   # missing key must not abort under 'set -euo pipefail'
}

API_PW=$(get_env API_PASSWORD)
if [ -n "$API_PW" ]; then
  # Test the API (returns 000 if container is down)
  HTTP_STATUS=$(docker compose $COMPOSE_OPTS exec -T wazuh.manager curl -sk -o /dev/null -w "%{http_code}" -X GET -u "wazuh-wui:$API_PW" https://127.0.0.1:55000/security/user/authenticate || echo "000")
  if [ "$HTTP_STATUS" = "401" ]; then
      echo "    [!] API Password mismatch detected! Scheduling rbac.db rebuild..."
      docker compose $COMPOSE_OPTS exec -T wazuh.manager rm -f /var/ossec/api/configuration/security/rbac.db
      FULL_RESTART=true
  else
      echo "    API Password is synchronized (Status: $HTTP_STATUS)"
  fi
fi

# -----------------------------------------------------------------------------
# 3.7. Sync ossec.conf and custom integrations from Git into Docker volumes
# -----------------------------------------------------------------------------
# Docker volumes persist across image builds. Files in volume paths (like /var/ossec/integrations
# and /var/ossec/etc) shadow any new files baked into the image. We explicitly sync them here.
echo "==> Syncing ossec.conf from Git into the Docker volume..."
if [ -f "$SINGLE_NODE_DIR/config/wazuh_cluster/wazuh_manager.conf" ]; then
  mkdir -p /opt/wazuh-secrets/wazuh-manager/
  
  # Export the webhook URLs so envsubst can use them
  export SLACK_WEBHOOK_URL=$(get_env SLACK_WEBHOOK_URL)
  export CLOUDTRAIL_SLACK_WEBHOOK_URL=$(get_env CLOUDTRAIL_SLACK_WEBHOOK_URL)
  # Fall back to the AR webhook if the CloudTrail one is missing OR empty
  [ -n "$CLOUDTRAIL_SLACK_WEBHOOK_URL" ] || export CLOUDTRAIL_SLACK_WEBHOOK_URL="$SLACK_WEBHOOK_URL"

  [ -n "$SLACK_WEBHOOK_URL" ] || echo "    WARNING: SLACK_WEBHOOK_URL is empty in .env.local — AR Slack alerts will fail."
  
  # Replace ${SLACK_WEBHOOK_URL} and ${CLOUDTRAIL_SLACK_WEBHOOK_URL} in the Git config and save to the secrets directory
  envsubst '${SLACK_WEBHOOK_URL} ${CLOUDTRAIL_SLACK_WEBHOOK_URL}' < "$SINGLE_NODE_DIR/config/wazuh_cluster/wazuh_manager.conf" > /opt/wazuh-secrets/wazuh-manager/ossec.conf
  
  # Now sync it into the running container
  docker compose $COMPOSE_OPTS exec -T wazuh.manager \
    cp /wazuh-config-mount/etc/ossec.conf /var/ossec/etc/ossec.conf
  echo "    ossec.conf synced successfully."
fi

# -----------------------------------------------------------------------------
# 4. Pull latest images and deploy
# -----------------------------------------------------------------------------
echo "==> [2/3] Pulling latest Docker images..."
docker compose $COMPOSE_OPTS pull -q --ignore-buildable

echo "==> [3/3] Deploying..."
if [ "$FULL_RESTART" = "true" ]; then
  echo "    Full restart required (new certificates or API password reset)"
  docker compose $COMPOSE_OPTS down
  docker compose $COMPOSE_OPTS up --build -d
  echo "    All services restarted with new certificates"
else
  echo "    Config-only deploy (restarting wazuh.manager to reload config)"
  docker compose $COMPOSE_OPTS up --build -d
  docker compose $COMPOSE_OPTS restart wazuh.manager
  echo "    wazuh.manager restarted with latest config"
fi

# -----------------------------------------------------------------------------
# 5. Sync custom integrations into the (now running) Docker volume
# -----------------------------------------------------------------------------
# Must run AFTER docker compose up --build so we target the correct container ID.
# The wazuh_integrations volume persists across image rebuilds, so files baked
# into the image are shadowed by the volume contents unless explicitly synced.
echo "==> Syncing custom-wazuh-slack integration into the Docker volume..."
if [ -f "$WAZUH_DIR/scripts/custom-wazuh-slack" ]; then
  MANAGER_CONTAINER=$(docker compose $COMPOSE_OPTS ps -q wazuh.manager 2>/dev/null || echo "")
  if [ -n "$MANAGER_CONTAINER" ]; then
    docker cp "$WAZUH_DIR/scripts/custom-wazuh-slack" "${MANAGER_CONTAINER}:/var/ossec/integrations/custom-wazuh-slack"
    docker compose $COMPOSE_OPTS exec -T wazuh.manager chown root:wazuh /var/ossec/integrations/custom-wazuh-slack
    docker compose $COMPOSE_OPTS exec -T wazuh.manager chmod 750 /var/ossec/integrations/custom-wazuh-slack
    echo "    custom-wazuh-slack synced successfully."
  else
    echo "    WARNING: wazuh.manager container not found, skipping custom-wazuh-slack sync."
  fi
fi

# -----------------------------------------------------------------------------
# 6. Sync custom rules into the (now running) Docker volume
# -----------------------------------------------------------------------------
# The wazuh_etc volume mounts over /var/ossec/etc/ (including /etc/rules/),
# shadowing anything COPY'd by the Dockerfile. Rules must be injected here
# after startup and wazuh-analysisd sent SIGHUP to hot-reload them.
echo "==> Syncing custom-cloudtrail-rules.xml into the Docker volume..."
if [ -f "$WAZUH_DIR/scripts/custom-cloudtrail-rules.xml" ]; then
  MANAGER_CONTAINER=$(docker compose $COMPOSE_OPTS ps -q wazuh.manager 2>/dev/null || echo "")
  if [ -n "$MANAGER_CONTAINER" ]; then
    docker cp "$WAZUH_DIR/scripts/custom-cloudtrail-rules.xml" "${MANAGER_CONTAINER}:/var/ossec/etc/rules/custom-cloudtrail-rules.xml"
    docker compose $COMPOSE_OPTS exec -T wazuh.manager chown root:wazuh /var/ossec/etc/rules/custom-cloudtrail-rules.xml
    docker compose $COMPOSE_OPTS exec -T wazuh.manager chmod 640 /var/ossec/etc/rules/custom-cloudtrail-rules.xml
    # Reload rules in wazuh.manager
    docker compose $COMPOSE_OPTS exec -T wazuh.manager /var/ossec/bin/wazuh-control reload || true
    echo "    custom-cloudtrail-rules.xml synced and wazuh-control reloaded."
  else
    echo "    WARNING: wazuh.manager container not found, skipping custom-cloudtrail-rules.xml sync."
  fi
fi

echo ""
echo "==> Deployment complete"
