"""Verify exported evidence with the standalone Rust port, then corrupt a copy."""

from __future__ import annotations

import json
import subprocess


def verify_export(authority, directory, binary):
    authority.admin("POST", "/admin/evidence/anchors", {})
    export_path = directory / "evidence.jsonl"
    export_text = authority.admin("GET", "/admin/evidence/export", raw=True)
    export_path.write_text(export_text)
    keys_path = directory / "executor-public-keys.json"
    keys_path.write_text(json.dumps(authority.admin("GET", "/admin/evidence/executor-keys")))
    anchors_path = directory / "held-anchors.json"
    anchors = authority.admin("GET", "/admin/evidence/anchors")
    anchors_path.write_text(json.dumps(anchors["anchors"]))
    options = [
        "--na-key",
        authority.public_key,
        "--executor-keys",
        str(keys_path),
        "--known-anchors",
        str(anchors_path),
        "--json",
    ]

    def verify(path):
        result = subprocess.run(
            [binary, "export", str(path), *options],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode not in {0, 1}:
            raise AssertionError(f"offline verifier exited {result.returncode}: {result.stderr}")
        return result.returncode, json.loads(result.stdout)

    good_code, good = verify(export_path)
    if good_code != 0 or good.get("verified") is not True or good.get("failures") != []:
        raise AssertionError("independent offline verifier rejected the original export")
    events = [json.loads(line) for line in export_text.splitlines() if line]
    if not events:
        raise AssertionError("the evidence export is empty")
    events[0]["payload"]["lab_tampered"] = True
    bad_path = directory / "tampered-evidence.jsonl"
    bad_path.write_text("\n".join(json.dumps(event) for event in events) + "\n")
    bad_code, bad = verify(bad_path)
    if bad_code != 1 or bad.get("verified") is not False or not bad.get("failures"):
        raise AssertionError("independent offline verifier accepted a corrupted export")
    return good, bad
