"""Disposable real NA and edge-agent processes used by the opt-in Linux lab.

Only test-created keys and databases are used. This module is not shipped in the
bridge wheel and never reads operator credentials from a configured deployment.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from genesismesh_radio.edge import EdgeClient, EdgeError


def wait_for(predicate, *, timeout=30, description="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (httpx.HTTPError, EdgeError, OSError):
            pass
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {description}")


class DisposableAuthority:
    def __init__(self, root: Path):
        from genesis_mesh.crypto import generate_keypair, sign_model
        from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef
        from genesis_mesh.na_service.server import NetworkAuthorityService

        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        self.root_key = generate_keypair()
        self.operator = generate_keypair()
        self.public_key = self.root_key.public_key_b64
        now = datetime.now(UTC)
        genesis = GenesisBlock(
            network_name="radio-disposable-lab",
            network_version="v0.1",
            root_public_key=self.public_key,
            network_authority=NetworkAuthority(
                public_key=self.public_key,
                valid_from=now,
                valid_to=now + timedelta(days=1),
            ),
            policy_manifest=PolicyManifestRef(hash="sha256:radio-lab", url=None),
        )
        genesis.signatures.append(sign_model(genesis, self.root_key.private_key, "root"))
        self.service = NetworkAuthorityService(
            genesis_block=genesis,
            na_private_key=self.root_key.private_key,
            key_id="na-radio-lab",
            db_path=str(root / "na.db"),
            operator_public_keys={"test-operator": self.operator.public_key_b64},
            operator_key_tiers={"test-operator": "privileged"},
            boundary_policy_enforcement="required",
            evidence_store="on",
            evidence_out_of_band="on",
            evidence_grants="on",
        )
        self.service.rate_limiter.allow = lambda *args, **kwargs: True
        self.port = 0
        self.server = None
        self.thread = None
        self.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        from werkzeug.serving import make_server

        self.server = make_server("127.0.0.1", self.port, self.service.app, threaded=True)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            self.server = None

    def admin(self, method, path, body=None, *, raw=False):
        from genesis_mesh.crypto.admin_auth import sign_admin_request

        headers = sign_admin_request(
            self.operator.private_key,
            "test-operator",
            method=method,
            path=path,
            audience=self.public_key,
            body=body,
        )
        with httpx.Client(timeout=15, trust_env=False) as client:
            response = client.request(method, self.url + path, headers=headers, json=body)
        if not response.is_success:
            # Test-only API errors are useful diagnostics, but never print requests or keys.
            result = response.json()
            code = result.get("error", {}).get("code", "unknown")
            raise AssertionError(f"test authority {method} {path}: {response.status_code} {code}")
        return response.text if raw else response.json()

    def provision(self, edge):
        node = edge.once("init", "--json")
        node_key = json.loads(node)["node_public_key"]
        invite = self.admin(
            "POST",
            "/admin/invite",
            {
                "roles": ["role:client"],
                "max_validity_hours": 24,
                "node_sovereign_id": "radio-lab",
                "executor_resource_prefix": "edge:radio-lab/",
                "recipient_public_key": node_key,
            },
        )
        token_path = edge.root / "invite.txt"
        token_path.write_text(invite["token_id"])
        token_path.chmod(0o600)
        edge.once("enroll", "--invite-token-file", str(token_path))
        token_path.unlink()
        enrollment = json.loads((edge.state / "enrollment.json").read_text())
        executor = enrollment["executor_key"]["key_id"]
        now = datetime.now(UTC)
        policy = self.admin(
            "POST",
            "/admin/boundary-policies",
            {
                "policy_id": "radio-lab-policy",
                "valid_from": (now - timedelta(minutes=1)).isoformat(),
                "valid_until": (now + timedelta(days=1)).isoformat(),
                "selector": {"capabilities": ["radio.command.dispatch"]},
                "gates": [
                    {
                        "gate_id": "interval",
                        "gate_type": "max_value.v1",
                        "order": 0,
                        "config": {"path": "request_parameters.interval_seconds", "max": 600},
                    }
                ],
            },
        )
        self.admin(
            "POST",
            "/admin/boundary-policies/radio-lab-policy/activate",
            {"version": policy["version"]},
        )
        attestation = self.admin(
            "POST",
            "/admin/attestations",
            {
                "subject_id": "radio-lab",
                "roles": ["role:client"],
                "claims": {"capabilities": ["radio.command.dispatch"]},
            },
        )
        grant = self.admin(
            "POST",
            "/admin/grants",
            {
                "bearer_key_id": executor,
                "capabilities": ["radio.command.dispatch"],
                "attestation_id": attestation["attestation_id"],
                "valid_until": (now + timedelta(hours=1)).isoformat(),
                "max_uses": 20,
                "max_uses_per_time_token": 10,
                "parameter_envelope": {
                    "interval_seconds": {
                        "number_range": {
                            "number_type": "integer",
                            "minimum": 5,
                            "maximum": 300,
                        }
                    }
                },
            },
        )
        return grant["grant"]["grant_id"]


class DisposableEdge:
    def __init__(self, root: Path, binary: str, authority: DisposableAuthority):
        self.root = root
        self.state = root / "edge-state"
        self.socket = root / "edge.sock"
        self.binary = binary
        self.config = root / "edge.toml"
        self.config.write_text(f'''[authority]
url = "{authority.url}"
root_public_key = "{authority.public_key}"
timeout_seconds = 2
[node]
state_dir = "{self.state}"
heartbeat_interval_seconds = 5
[snapshot]
sync_interval_seconds = 5
retry_interval_seconds = 1
max_snapshot_age_seconds = 60
[local_api]
listen = "unix:{self.socket}"
allowed_uids = [{os.getuid()}]
report_timeout_seconds = 30
queue_timeout_seconds = 1
rate_limit_per_minute = 1000
''')
        self.env = {
            key: value for key, value in os.environ.items() if not key.startswith("GM_EDGE_")
        }
        self.env["GM_EDGE_CONFIG"] = str(self.config)
        self.process = None
        self.log = None

    def once(self, *args):
        result = subprocess.run(
            [self.binary, *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise AssertionError(f"test edge {args[0]} exited {result.returncode}: {result.stderr}")
        return result.stdout

    def start(self):
        self.log = (self.root / "edge.log").open("a")
        self.process = subprocess.Popen(
            [self.binary, "run"], env=self.env, stdout=self.log, stderr=self.log
        )
        with EdgeClient(unix_socket=str(self.socket)) as client:
            wait_for(lambda: client.status().get("state"), description="ready edge API")

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def expire_snapshot(self):
        """Move only this stopped disposable agent's cache timestamp back in time."""
        self.stop()
        snapshot_path = self.state / "snapshot.json"
        snapshot = json.loads(snapshot_path.read_text())
        snapshot["synced_at"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        snapshot_path.write_text(json.dumps(snapshot))
        snapshot_path.chmod(0o600)
        self.start()


@contextlib.contextmanager
def running_stack(root: Path, binary: str):
    authority = DisposableAuthority(root)
    edge = DisposableEdge(root, binary, authority)
    try:
        grant_id = authority.provision(edge)
        edge.start()
        yield authority, edge, grant_id
    finally:
        edge.stop()
        authority.stop()
