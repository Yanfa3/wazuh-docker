"""Offline response tests. No Cloudflare, Slack, firewall, or Docker calls."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cf = load_script("cloudflare_block", "scripts/cloudflare-block.py")
policy = load_script("repeat_policy", "scripts/configure-repeat-offenders.py")
IP = "192.0.2.10"
ALERT = {"id": "1234567890.42", "rule": {"id": "31151"}, "data": {"srcip": IP}}


def rule(notes, rule_id="owned"):
    return {"id": rule_id, "mode": "block", "notes": notes,
            "configuration": {"target": "ip", "value": IP}}


class CloudflareTests(unittest.TestCase):
    def setUp(self):
        patches = [patch.object(cf, "log"), patch.object(cf, "send_slack"),
                   patch.object(cf, "SAFE_IPS", ["127.0.0.1"])]
        self.log, self.slack, _ = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)

    def invoke(self, command="add", temporary=True, reply="continue", alert=None):
        payload = {"command": command, "parameters": {
            "extra_args": ["--temporary"] if temporary else [],
            "alert": alert if alert is not None else ALERT,
        }}
        data = json.dumps(payload) + "\n" + json.dumps({"command": reply}) + "\n"
        output = io.StringIO()
        with patch.object(cf.sys, "stdin", io.StringIO(data)), contextlib.redirect_stdout(output):
            result = cf.main()
        return result, output.getvalue()

    def test_continue_registers_ip_then_blocks(self):
        with patch.object(cf, "block_ip") as block:
            result, output = self.invoke()
        self.assertIsNone(result)
        message = json.loads(output)
        self.assertEqual(message["command"], "check_keys")
        self.assertEqual(message["parameters"]["keys"], [IP])
        block.assert_called_once_with(IP, ALERT, True)

    def test_abort_refresh_is_owned_by_wazuh_without_api_call(self):
        with patch.object(cf, "api_request") as api:
            self.invoke(reply="abort")
        api.assert_not_called()

    def test_invalid_handshake_and_eof_fail_without_api_call(self):
        with patch.object(cf, "api_request") as api:
            result, _ = self.invoke(reply="unexpected")
            self.assertEqual(result, 1)
            with patch.object(cf.sys, "stdin", io.StringIO("")), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):
                    cf.check_keys(IP)
        api.assert_not_called()

    def test_permanent_add_does_not_handshake(self):
        with patch.object(cf, "block_ip") as block:
            _, output = self.invoke(temporary=False)
        self.assertEqual(output, "")
        block.assert_called_once_with(IP, ALERT, False)

    def test_permanent_delete_is_ignored(self):
        with patch.object(cf, "api_request") as api:
            self.invoke(command="delete", temporary=False)
        api.assert_not_called()

    def test_invalid_missing_and_safe_ips_never_reach_handshake_or_api(self):
        with patch.object(cf, "api_request") as api:
            for address in (None, "host.example", "127.0.0.1"):
                _, output = self.invoke(alert={**ALERT, "data": {"srcip": address}})
                self.assertEqual(output, "")
        api.assert_not_called()

    def test_missing_alert_id_does_not_register_timer(self):
        with patch.object(cf, "api_request") as api:
            result, output = self.invoke(alert={"data": {"srcip": IP}})
        self.assertEqual(result, 1)
        self.assertEqual(output, "")
        api.assert_not_called()

    def test_new_temporary_rule_has_ownership_marker(self):
        with patch.object(cf, "api_request", side_effect=[{"result": []}, {"success": True}]) as api:
            cf.block_ip(IP, ALERT, temporary=True)
        created = api.call_args.kwargs["payload"]
        self.assertEqual(created["notes"], cf.temporary_notes(ALERT))
        self.assertEqual(created["configuration"], {"target": "ip", "value": IP})
        self.assertEqual(api.call_args.args, ("POST",))

    def test_existing_rules_are_not_adopted_by_temporary_response(self):
        for notes in ("manual", cf.PERMANENT_NOTES, cf.TEMPORARY_NOTES_PREFIX + "older-alert"):
            with self.subTest(notes=notes), patch.object(cf, "api_request", return_value={"result": [rule(notes)]}) as api:
                cf.block_ip(IP, ALERT, temporary=True)
                self.assertEqual(api.call_count, 1)
        self.slack.assert_not_called()

    def test_expiry_deletes_only_owned_generation(self):
        entries = [rule("manual", "manual"), rule(cf.PERMANENT_NOTES, "permanent"),
                   rule(cf.TEMPORARY_NOTES_PREFIX + "newer-alert", "newer"),
                   rule(cf.temporary_notes(ALERT))]
        with patch.object(cf, "api_request", side_effect=[{"result": entries}, {"success": True}]) as api:
            _, output = self.invoke(command="delete")
        self.assertEqual(output, "")
        self.assertEqual(api.call_args.args, ("DELETE", "/owned"))
        self.assertEqual(api.call_count, 2)
        self.slack.assert_called_once()

    def test_permanent_detection_promotes_temporary_rule(self):
        entry = rule(cf.temporary_notes(ALERT))
        with patch.object(cf, "api_request", side_effect=[{"result": [entry]}, {"success": True}]) as api:
            cf.block_ip(IP, ALERT)
        self.assertEqual(api.call_args.args, ("PATCH", "/owned", {
            "mode": "block", "notes": cf.PERMANENT_NOTES}))
        with patch.object(cf, "api_request", return_value={"result": [rule(cf.PERMANENT_NOTES)]}) as api:
            cf.unblock_ip(IP, ALERT)
            self.assertEqual(api.call_count, 1)

    def test_failed_delete_never_claims_success(self):
        with patch.object(cf, "api_request", side_effect=[
                {"result": [rule(cf.temporary_notes(ALERT))]}, RuntimeError("API unavailable")]):
            result, _ = self.invoke(command="delete")
        self.assertEqual(result, 1)
        self.assertIn("block may remain", self.slack.call_args.args[0])
        self.assertFalse(any("Successfully" in call.args[0] for call in self.log.call_args_list))

    def test_lookup_filters_unrelated_rules_and_refuses_extra_pages(self):
        with patch.object(cf, "api_request", return_value={"result": [
                rule("manual"), {**rule("other"), "configuration": {"target": "ip", "value": "192.0.2.11"}}]}):
            self.assertEqual(len(cf.matching_rules(IP)), 1)
        with patch.object(cf, "api_request", return_value={"result_info": {"total_pages": 2}}):
            with self.assertRaises(RuntimeError):
                cf.matching_rules(IP)

    def test_ipv6_uses_ip6_target(self):
        with patch.object(cf, "api_request", side_effect=[{"result": []}, {"success": True}]) as api:
            cf.block_ip("2001:db8::1", ALERT, temporary=True)
        self.assertEqual(api.call_args.kwargs["payload"]["configuration"]["target"], "ip6")

    def test_api_rejection_is_failure_and_does_not_expose_http_body(self):
        with patch.object(cf.urllib.request, "urlopen", return_value=io.StringIO('{"success": false, "errors": []}')):
            with self.assertRaises(RuntimeError):
                cf.api_request("DELETE", "/owned")
        error = urllib.error.HTTPError("https://example.invalid", 403, "Forbidden", {}, io.BytesIO(b"secret"))
        with patch.object(cf.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "^Cloudflare HTTP 403$"):
                cf.api_request("GET")

    def test_notifications_describe_policy_without_inventing_expiry(self):
        temporary = cf.build_slack_payload(ALERT, "ADD", IP, temporary=True)
        permanent = cf.build_slack_payload(ALERT, "ADD", IP)
        self.assertIn("native repeat-offender timeout", json.dumps(temporary))
        self.assertIn("Permanent", json.dumps(permanent))


class ConfigurationTests(unittest.TestCase):
    def test_helper_validates_backs_up_and_preserves_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            config = root / "etc/ossec.conf"
            original = '<ossec_config><active-response><disabled>no</disabled></active-response></ossec_config>'
            config.write_text(original)
            config.chmod(0o640)
            with patch.object(policy.subprocess, "run") as validate, \
                    patch.object(policy.os, "chown", wraps=os.chown) as chown, \
                    patch("sys.argv", ["configure-repeat-offenders.py", "--root", directory]), \
                    contextlib.redirect_stdout(io.StringIO()):
                policy.main()
            self.assertEqual(validate.call_args.args[0][:3],
                             [str(root / "bin/wazuh-execd"), "-t", "-c"])
            self.assertIn(policy.POLICY, config.read_text())
            backups = list((root / "etc").glob("ossec.conf.before-repeat-policy-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), original)
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)
            chown.assert_called_once()

    def test_failed_native_validation_leaves_config_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            config = root / "etc/ossec.conf"
            original = '<ossec_config><active-response><disabled>no</disabled></active-response></ossec_config>'
            config.write_text(original)
            with patch.object(policy.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "wazuh-execd")), \
                    patch("sys.argv", ["configure-repeat-offenders.py", "--root", directory]):
                with self.assertRaises(subprocess.CalledProcessError):
                    policy.main()
            self.assertEqual(config.read_text(), original)
            self.assertEqual(list((root / "etc").iterdir()), [config])

    def test_manager_policy_and_response_mappings(self):
        root = ET.fromstring((ROOT / "single-node/config/wazuh_cluster/wazuh_manager.conf").read_text())
        self.assertEqual(root.findtext("active-response/repeated_offenders"), policy.POLICY)
        commands = {entry.findtext("name"): entry for entry in root.findall("command")}
        responses = root.findall("active-response")
        rule_responses = [entry for entry in responses if entry.findtext("rules_id") == "31151"]
        self.assertEqual({entry.findtext("command") for entry in rule_responses},
                         {"firewall-drop", "cloudflare-block-temporary"})
        for entry in rule_responses:
            self.assertEqual(entry.findtext("timeout"), "3600")
            self.assertEqual(commands[entry.findtext("command")].findtext("timeout_allowed"), "yes")
        permanent = [entry for entry in responses if entry.findtext("command") == "cloudflare-block"]
        self.assertEqual(len(permanent), 1)
        self.assertEqual(permanent[0].findtext("rules_id"), "31152, 31153, 31154")

    def test_agent_template_has_same_policy(self):
        text = (ROOT / "wazuh-agent/config/wazuh-agent-conf").read_text()
        self.assertEqual(policy.updated_config(text), text)

    def test_agent_update_preserves_configuration_and_is_idempotent(self):
        original = ('<ossec_config><!-- preserve --><active-response><disabled>no</disabled>'
                    '<ca_store>etc/wpk_root.pem</ca_store></active-response></ossec_config>'
                    '<ossec_config><localfile><location>/tmp/test</location></localfile></ossec_config>')
        updated = policy.updated_config(original)
        self.assertIn("<!-- preserve -->", updated)
        self.assertIn("<ca_store>etc/wpk_root.pem</ca_store>", updated)
        self.assertIn("<location>/tmp/test</location>", updated)
        self.assertEqual(policy.updated_config(updated), updated)

    def test_agent_update_replaces_existing_schedule(self):
        original = '<ossec_config><active-response><disabled>no</disabled><repeated_offenders>10,20</repeated_offenders></active-response></ossec_config>'
        updated = policy.updated_config(original)
        self.assertNotIn("10,20", updated)
        self.assertIn(policy.POLICY, updated)

    def test_agent_update_refuses_disabled_or_ambiguous_policy(self):
        for block in ('<active-response><disabled>yes</disabled></active-response>',
                      '<active-response/><active-response/>'):
            # Use full tags because the updater preserves existing XML text.
            block = block.replace('<active-response/>', '<active-response></active-response>')
            with self.assertRaises(ValueError):
                policy.updated_config('<ossec_config>' + block + '</ossec_config>')


if __name__ == "__main__":
    unittest.main()
