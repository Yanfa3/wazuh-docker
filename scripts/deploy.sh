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

# -----------------------------------------------------------------------------
# 1. Pull latest code
# -----------------------------------------------------------------------------
echo "==> [1/4] Pulling latest code from origin/master..."
cd "$WAZUH_DIR"
git fetch origin master
git reset --hard origin/master
cd "$SINGLE_NODE_DIR"

# -----------------------------------------------------------------------------
# 2. Validate SSL certificate health
# -----------------------------------------------------------------------------
echo "==> [2/4] Validating SSL certificates..."
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
# 4. Pull latest images and deploy
# -----------------------------------------------------------------------------
echo "==> [3/4] Pulling latest Docker images..."
docker compose $COMPOSE_OPTS pull -q

echo "==> [4/4] Deploying..."
if [ "$FULL_RESTART" = "true" ]; then
  echo "    Full restart required (new certificates)"
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
