#!/bin/bash
# Script to forcefully synchronize the wazuh-wui API password in the Manager's rbac.db
# with the API_PASSWORD from the .env.local file.

set -euo pipefail

WAZUH_DIR="/home/yanfaa/wazuh-docker"
COMPOSE_OPTS="--env-file $WAZUH_DIR/.env --env-file $WAZUH_DIR/.env.local"

cd "$WAZUH_DIR/single-node"

echo "==> Fetching current API_PASSWORD from environment..."
API_PW=$(docker compose $COMPOSE_OPTS config | grep -oP '(?<=API_PASSWORD: ).*' | tr -d '\r' | tr -d '"' | tr -d "'")

if [ -z "$API_PW" ]; then
    echo "ERROR: Could not find API_PASSWORD in docker-compose environment."
    exit 1
fi

echo "==> Resetting wazuh-wui password inside the manager container..."
docker compose $COMPOSE_OPTS exec -T -e NEW_PW="$API_PW" wazuh.manager /var/ossec/framework/python/bin/python3 -c "
import sys, os
sys.path.append('/var/ossec/framework/python/lib/python3.9/site-packages')
from wazuh.rbac.orm import AuthenticationManager
try:
    auth = AuthenticationManager()
    # Find user ID for wazuh-wui
    with auth._session() as session:
        from wazuh.rbac.models import User
        user = session.query(User).filter_by(username='wazuh-wui').first()
        if not user:
            print('Error: wazuh-wui user not found in rbac.db')
            sys.exit(1)
        user_id = user.id
    # Update password securely via env var
    auth.update_user(user_id=user_id, password=os.environ.get('NEW_PW'))
    print('Successfully updated password for wazuh-wui.')
except Exception as e:
    print(f'Error updating password: {e}')
    sys.exit(1)
"

echo "==> Restarting Dashboard to reconnect to API..."
docker compose $COMPOSE_OPTS restart wazuh.dashboard

echo "Done!"
