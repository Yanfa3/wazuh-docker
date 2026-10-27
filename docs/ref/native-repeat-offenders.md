# Native repeat-offender policy for rule 31151

## Policy

New rule 31151 responses start with a 3,600-second timeout at the endpoint
firewall and Cloudflare. Native `repeated_offenders=120,1440,10080` then
selects 2 hours, 24 hours, and 7 days; the final duration repeats.

The repeat setting applies to all timed responses on each configured host.
Other responses retain their initial timeout and permanent commands remain
permanent. Existing local and Cloudflare permanent bans are not migrated.
Rules 31152–31154 keep their permanent Cloudflare response.

This is Wazuh 4.14.7 native behavior, not a count of completed bans within
a seven-day window. Detections during an active block can advance the
repeat counter and reset its expiry. Counts are held in memory per response
executable and keys on each execution host. They reset when execd restarts.
Endpoint and manager counts can therefore differ. A clean execd shutdown
reverts pending temporary responses; a crash can leave blocks behind.

Cloudflare temporary rules carry an ownership marker containing the original
alert ID. Expiry deletes only that generation's rule, preserving existing,
manual, permanent, and newer rules. A permanent detection promotes an owned
temporary rule before its pending expiry. No SQLite database is used.
Cloudflare API failures are logged and reported; failed deletion may leave a
block in place and there is no independent cleanup scheduler.

## Validate before deployment

The changed files must first be available in the server checkout. Local
workspace edits are not automatically published or copied to production.
Do not run the deployment against an older checkout.

From the updated checkout:

```bash
python3 -m unittest discover -s tests -v
```

On the manager host, validate the new configuration in an isolated container
using the existing custom image. This starts no Wazuh services, has no network
access, and mounts only the candidate configuration, read-only:

The image stores default runtime files under `data_tmp` until its startup
initialization. Because validation bypasses startup, restore those files
inside the disposable container before invoking the parsers.

```bash
cd /home/yanfaa/wazuh-docker
sudo docker run --rm --network none \
  --entrypoint /bin/bash \
  -v "$PWD/single-node/config/wazuh_cluster/wazuh_manager.conf:/candidate-ossec.conf:ro" \
  custom-wazuh-manager:4.14.7 \
  -c '
    set -e -o pipefail
    cp -a /var/ossec/data_tmp/permanent/var/ossec/. /var/ossec/
    cp -a /var/ossec/data_tmp/exclusion/var/ossec/. /var/ossec/
    cp /candidate-ossec.conf /var/ossec/etc/ossec.conf
    chown -R wazuh:wazuh /var/ossec/etc/lists /var/ossec/queue/rids
    /var/ossec/bin/wazuh-execd -t 2>&1 | tee /tmp/execd-validation.log
    /var/ossec/bin/wazuh-analysisd -t 2>&1 | tee /tmp/analysisd-validation.log
    if grep -Eq "(ERROR|CRITICAL):" /tmp/execd-validation.log /tmp/analysisd-validation.log; then
      echo "Validation failed: Wazuh logged errors"
      exit 1
    fi
    echo "Wazuh configuration validation passed"
  '
```

Both checks must succeed. This validates the configuration with Wazuh's
parser; it does not validate real Cloudflare API permissions or elapsed-time
behavior. In a disposable environment, test shortened initial/repeat
timeouts, duplicate alerts during a block, expiry, clean shutdown, and crash
recovery before treating end-to-end behavior as verified. Use mocked API
responses rather than creating test rules in the production account.

## Activate

1. Back up the current manager configuration, custom response script, Slack
   integration, and `/opt/wazuh-secrets/wazuh-manager/ossec.conf`. Keep a copy
   of the previous custom manager image for rollback.
2. For manual manager-only activation from the updated checkout, run
   `sudo bash scripts/deploy-native-repeat-policy.sh /home/yanfaa/wazuh-docker`.
   This makes the backups above, retains the old image under a timestamped
   tag, rebuilds and validates the new image in isolation, synchronizes the
   rendered configuration and Slack integration, and recreates only the
   manager. It reports its backup directory and leaves agents for a separate
   step. It requires a populated `.env.local` and a running manager. If it
   fails, stop and inspect the error before proceeding. For subsequent normal
   releases, the existing deployment workflow also installs these changes.
   Deploying XML alone is insufficient: the response script must match it.
3. Copy `scripts/configure-repeat-offenders.py` to each active Linux agent:
   agent 003 on 5.9.50.120, agent 002 on 108.181.240.25, and agent 005 on
   108.181.242.10. The helper requires Python 3.6 or later. Run the following
   on one agent at a time, using the actual path of the copied script:

   ```bash
   hostname
   sudo python3 /tmp/configure-repeat-offenders.py
   sudo systemctl restart wazuh-agent
   sudo /var/ossec/bin/wazuh-control status
   sudo sed -n '/<active-response>/,/<\/active-response>/p' /var/ossec/etc/ossec.conf
   ```

   Stop if the helper fails. It validates a candidate with the installed
   `wazuh-execd -t -c`, makes a timestamped backup beside `ossec.conf`, and
   replaces the configuration atomically while preserving owner and mode.
   It does not restart services. Confirm all daemons return to running before
   moving to the next host. This setting must be local, not in `agent.conf`.

After manager deployment:

```bash
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
sudo docker exec single-node-wazuh.manager-1 cat /var/ossec/etc/shared/ar.conf
sudo docker exec single-node-wazuh.manager-1 sh -c \
  'grep "Adding offenders timeout" /var/ossec/logs/ossec.log | tail -n 6'
```

Expect `cloudflare-block-temporary3600` and `firewall-drop3600` response
entries, plus native startup timeout messages for 120, 1440, and 10080
minutes. Check each agent's startup log for the same repeat timeout messages.
Observe a real block and successful removal through a complete timeout
cycle. Rule 651 records invocation, not independent proof of packet filtering.

For rollback, restore each agent's exact backup path and restart it. Restore
the manager's saved configuration, rendered secrets file, scripts, and
previous image, then restart the manager. Native repeat history resets;
do not remove historical bans as part of rollback.

## References

- [Repeat offenders configuration](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/additional-information.html)
- [Native 4.14.7 timeout and repeat handling](https://github.com/wazuh/wazuh/blob/v4.14.7/src/os_execd/execd.c)
- [Custom stateful response protocol](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
