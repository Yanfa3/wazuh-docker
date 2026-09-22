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
API_PW=$(grep -oP '(?<=API_PASSWORD=).*' "$WAZUH_DIR/.env.local" || true)
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
# 3.7. Sync ossec.conf from host mount into the Docker volume
# -----------------------------------------------------------------------------
# The Wazuh container only copies /wazuh-config-mount/etc/ossec.conf into the
# persistent wazuh_etc volume on FIRST BOOT. Every subsequent restart reads the
# cached copy from the volume, completely ignoring any changes to the host file.
# This step forces the sync on every deploy so the container always runs with
# the latest configuration from /opt/wazuh-secrets/wazuh-manager/ossec.conf.
echo "==> Syncing ossec.conf from host into the Docker volume..."
if [ -f "/opt/wazuh-secrets/wazuh-manager/ossec.conf" ]; then
  docker compose $COMPOSE_OPTS exec -T wazuh.manager \
    cp /wazuh-config-mount/etc/ossec.conf /var/ossec/etc/ossec.conf
  echo "    ossec.conf synced successfully."
fi

# -----------------------------------------------------------------------------
# 4. Pull latest images and deploy
# -----------------------------------------------------------------------------
echo "==> [2/3] Pulling latest Docker images..."
docker compose $COMPOSE_OPTS pull -q

echo "==> [3/3] Deploying..."
if [ "$FULL_RESTART" = "true" ]; then
  echo "    Full restart required (new certificates or API password reset)"
  docker compose $COMPOSE_OPTS down
  docker compose $COMPOSE_OPTS up -d
  echo "    All services restarted with new certificates"
else
  echo "    Config-only deploy (restarting wazuh.manager to reload config)"
  docker compose $COMPOSE_OPTS up -d
  docker compose $COMPOSE_OPTS restart wazuh.manager
  echo "    wazuh.manager restarted with latest config"
fi

echo ""
echo "==> Deployment complete"
