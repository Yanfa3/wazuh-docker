#!/usr/bin/env python3
"""Set the local Wazuh repeat policy; validate and back up before replacing config.

Run as root on each Linux agent. This does not restart any service.
"""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET


POLICY = "120,1440,10080"


def updated_config(text):
    # Wazuh permits multiple ossec_config roots. Preserve comments and formatting.
    ET.fromstring("<config>" + text + "</config>")
    candidates = []
    for match in re.finditer(r"<active-response>.*?</active-response>", text, re.S):
        element = ET.fromstring(match.group())
        if element.find("command") is None:
            candidates.append(match)
    if len(candidates) > 1:
        raise ValueError("Multiple local active-response sections; manual review required")
    if candidates:
        match = candidates[0]
        block = match.group()
        element = ET.fromstring(block)
        if element.findtext("disabled", "no").strip() != "no":
            raise ValueError("Active response is disabled; refusing to enable it implicitly")
        if len(element.findall("repeated_offenders")) > 1:
            raise ValueError("Duplicate repeated_offenders settings")
        if element.find("repeated_offenders") is not None:
            block = re.sub(r"<repeated_offenders>.*?</repeated_offenders>",
                           f"<repeated_offenders>{POLICY}</repeated_offenders>", block, flags=re.S)
        else:
            block = block.replace("</active-response>",
                                  f"  <repeated_offenders>{POLICY}</repeated_offenders>\n  </active-response>")
        result = text[:match.start()] + block + text[match.end():]
    else:
        block = ("  <active-response>\n    <disabled>no</disabled>\n"
                 f"    <repeated_offenders>{POLICY}</repeated_offenders>\n"
                 "  </active-response>\n")
        result = text.replace("</ossec_config>", block + "</ossec_config>", 1)
        if result == text:
            raise ValueError("No ossec_config root found")
    ET.fromstring("<config>" + result + "</config>")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/var/ossec"))
    args = parser.parse_args()
    config = args.root / "etc/ossec.conf"
    original = config.read_text()
    updated = updated_config(original)
    if updated == original:
        print(f"Already configured: {POLICY}; service was not restarted")
        return
    # Validate using the installed Wazuh parser before touching the live config.
    fd, candidate_name = tempfile.mkstemp(prefix=".repeat-policy-", dir=config.parent)
    try:
        with os.fdopen(fd, "w") as candidate:
            candidate.write(updated)
            candidate.flush()
            os.fsync(candidate.fileno())
        subprocess.run([str(args.root / "bin/wazuh-execd"), "-t", "-c", candidate_name], check=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        backup = config.with_name(f"ossec.conf.before-repeat-policy-{stamp}")
        shutil.copy2(config, backup)
        metadata = config.stat()
        os.chown(candidate_name, metadata.st_uid, metadata.st_gid)
        shutil.copystat(config, candidate_name)
        os.replace(candidate_name, config)
    finally:
        if os.path.exists(candidate_name):
            os.unlink(candidate_name)
    print(f"Backup: {backup}")
    print(f"Configured: {POLICY}; restart wazuh-agent to activate")


if __name__ == "__main__":
    main()
