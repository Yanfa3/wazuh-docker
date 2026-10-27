#!/bin/bash
# Run manually as root after applying the policy patch. Deploys the manager only.
set -euo pipefail
umask 077

REPO_DIR="${1:-/home/yanfaa/wazuh-docker}"
cd "$REPO_DIR"
REPO_DIR="$PWD"
COMPOSE=(docker compose --project-directory "$REPO_DIR/single-node"
  --env-file "$REPO_DIR/.env" --env-file "$REPO_DIR/.env.local"
  -f "$REPO_DIR/single-node/docker-compose.yml")
SECRET_CONFIG=/opt/wazuh-secrets/wazuh-manager/ossec.conf

test -f "$SECRET_CONFIG"
python3 -m unittest discover -s tests -v
"${COMPOSE[@]}" config --quiet
MANAGER_ID=$("${COMPOSE[@]}" ps -q wazuh.manager)
test -n "$MANAGER_ID"
BACKUP_DIR=$(mktemp -d /opt/wazuh-secrets/native-repeat-policy-backup.XXXXXXXX)
echo "Backup directory: $BACKUP_DIR"
trap 'echo "Deployment failed. Keep backup directory: $BACKUP_DIR" >&2' ERR

docker cp "$MANAGER_ID:/var/ossec/etc/ossec.conf" "$BACKUP_DIR/live-ossec.conf"
docker cp "$MANAGER_ID:/var/ossec/active-response/bin/cloudflare-block" "$BACKUP_DIR/cloudflare-block"
docker cp "$MANAGER_ID:/var/ossec/integrations/custom-wazuh-slack" "$BACKUP_DIR/custom-wazuh-slack"
cp -p "$SECRET_CONFIG" "$BACKUP_DIR/rendered-ossec.conf"
OLD_IMAGE=$(docker inspect --format '{{.Image}}' "$MANAGER_ID")
OLD_TAG="custom-wazuh-manager:before-native-repeat-$(date -u +%Y%m%dT%H%M%SZ)"
docker image tag "$OLD_IMAGE" "$OLD_TAG"
printf '%s\n' "$OLD_TAG" > "$BACKUP_DIR/previous-image-tag"

# Render the same two webhook substitutions as deploy.sh, without printing secrets.
python3 - "$REPO_DIR" "$BACKUP_DIR/candidate-ossec.conf" <<'PY'
from html import escape
from pathlib import Path
import runpy
import sys

repo = Path(sys.argv[1])
load_env = runpy.run_path(str(repo / "scripts/cloudflare-block.py"))["load_env"]
env = load_env(str(repo / ".env.local"))
webhook = env.get("SLACK_WEBHOOK_URL", "")
cloudtrail = env.get("CLOUDTRAIL_SLACK_WEBHOOK_URL") or webhook
if not webhook:
    raise SystemExit("SLACK_WEBHOOK_URL is missing; no live configuration was changed")
text = (repo / "single-node/config/wazuh_cluster/wazuh_manager.conf").read_text()
text = text.replace("${SLACK_WEBHOOK_URL}", escape(webhook, quote=False))
text = text.replace("${CLOUDTRAIL_SLACK_WEBHOOK_URL}", escape(cloudtrail, quote=False))
Path(sys.argv[2]).write_text(text)
PY

"${COMPOSE[@]}" build wazuh.manager

# Validate the newly built image, with no production volumes or network access.
docker run --rm --network none --entrypoint /bin/bash \
  -v "$BACKUP_DIR/candidate-ossec.conf:/candidate-ossec.conf:ro" \
  custom-wazuh-manager:4.14.7 -c '
    set -e -o pipefail
    cp -a /var/ossec/data_tmp/permanent/var/ossec/. /var/ossec/
    cp -a /var/ossec/data_tmp/exclusion/var/ossec/. /var/ossec/
    cp /candidate-ossec.conf /var/ossec/etc/ossec.conf
    chown -R wazuh:wazuh /var/ossec/etc/lists /var/ossec/queue/rids
    /var/ossec/bin/wazuh-execd -t 2>&1 | tee /tmp/execd-validation.log
    /var/ossec/bin/wazuh-analysisd -t 2>&1 | tee /tmp/analysisd-validation.log
    if grep -Eq "(ERROR|CRITICAL):" /tmp/execd-validation.log /tmp/analysisd-validation.log; then
      exit 1
    fi
  '

# Preserve the bind mount inode and permissions; sync persistent configuration.
cat "$BACKUP_DIR/candidate-ossec.conf" > "$SECRET_CONFIG"
docker cp "$BACKUP_DIR/candidate-ossec.conf" "$MANAGER_ID:/var/ossec/etc/ossec.conf"
docker exec "$MANAGER_ID" chown root:wazuh /var/ossec/etc/ossec.conf
docker exec "$MANAGER_ID" chmod 640 /var/ossec/etc/ossec.conf
docker cp "$REPO_DIR/scripts/custom-wazuh-slack" "$MANAGER_ID:/var/ossec/integrations/custom-wazuh-slack"
docker exec "$MANAGER_ID" chown root:wazuh /var/ossec/integrations/custom-wazuh-slack
docker exec "$MANAGER_ID" chmod 750 /var/ossec/integrations/custom-wazuh-slack
"${COMPOSE[@]}" up -d --no-deps --force-recreate wazuh.manager

MANAGER_ID=$("${COMPOSE[@]}" ps -q wazuh.manager)
for attempt in $(seq 1 60); do
  if docker exec "$MANAGER_ID" cat /var/ossec/etc/shared/ar.conf 2>/dev/null \
      | grep -q '^cloudflare-block-temporary3600 '; then
    # status returns nonzero for optional daemons that are intentionally disabled.
    STATUS=$(docker exec "$MANAGER_ID" /var/ossec/bin/wazuh-control status || true)
    echo "$STATUS"
    READY=true
    for daemon in wazuh-execd wazuh-analysisd wazuh-remoted wazuh-db wazuh-integratord; do
      if ! grep -Fxq "$daemon is running..." <<< "$STATUS"; then
        READY=false
      fi
    done
    if [ "$READY" != true ]; then
      sleep 2
      continue
    fi
    docker exec "$MANAGER_ID" cat /var/ossec/etc/shared/ar.conf
    echo "Manager response configuration activated. Backup: $BACKUP_DIR"
    echo "Agent-local repeat policies must still be configured and verified."
    exit 0
  fi
  sleep 2
done
echo "Manager response configuration did not appear; inspect manager logs before proceeding." >&2
exit 1
