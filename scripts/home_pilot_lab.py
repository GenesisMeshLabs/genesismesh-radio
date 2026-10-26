#!/usr/bin/env python3
"""Rehearse a private home pilot with real GenesisMesh services and simulated RF."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "integration"))
if os.environ.get("GM_CORE_SOURCE"):
    sys.path.insert(0, os.environ["GM_CORE_SOURCE"])

CORE_REVISION = "9e4d5c01e6ba7a22e73c17388796ec274f73a2fc"
SDK_REVISION = "e554ca482a3ef4bc1e7a2ef205ac1d537daa169d"
RUNTIME_VERSION = "1.8.1"
MAX_BINARY_BYTES = 512 * 1024 * 1024


class LabError(RuntimeError):
    """A redacted refusal code; never includes requests, credentials or raw traces."""


def git_value(directory, *arguments):
    result = subprocess.run(
        ["git", "-C", str(directory), *arguments],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode:
        raise LabError("source_revision_unavailable")
    return result.stdout.strip()


def binary_info(path, expected_name):
    path = Path(path).resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BINARY_BYTES:
        raise LabError("invalid_runtime_binary")
    version = subprocess.run(
        [str(path), "--version"], capture_output=True, text=True, timeout=10, check=False
    )
    expected = f"{expected_name} {RUNTIME_VERSION}"
    if version.returncode or version.stdout.strip() != expected:
        raise LabError("unexpected_runtime_version")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {"version": expected, "sha256": digest.hexdigest()}


def runtime_info(edge_binary, verify_binary):
    import genesis_mesh

    core_root = Path(genesis_mesh.__file__).resolve().parent.parent
    manifest = tomllib.loads((core_root / "pyproject.toml").read_text())
    revision = git_value(core_root, "rev-parse", "HEAD")
    if (
        manifest["project"]["name"] != "genesis-mesh"
        or manifest["project"]["version"] != RUNTIME_VERSION
        or genesis_mesh.__version__ != RUNTIME_VERSION
        or revision != CORE_REVISION
        or git_value(core_root, "status", "--porcelain", "--untracked-files=normal")
    ):
        raise LabError("pinned_core_source_required")
    return {
        "radio_source_commit": git_value(ROOT, "rev-parse", "HEAD"),
        "radio_working_tree_clean": not git_value(
            ROOT, "status", "--porcelain", "--untracked-files=normal"
        ),
        "core_source_commit": revision,
        "core_version": RUNTIME_VERSION,
        "expected_sdk_source_commit": SDK_REVISION,
        "binary_provenance": (
            "versions_and_file_hashes; SDK build source not independently attested"
        ),
        "edge": binary_info(edge_binary, "genesis-mesh-edge"),
        "verifier": binary_info(verify_binary, "genesis-mesh-verify"),
        "python": platform.python_version(),
    }


def check(report, name, condition):
    if not re.fullmatch(r"(?:home|console)_[a-z0-9_]{1,100}", name):
        raise LabError("invalid_check_name")
    if not condition:
        raise LabError(name)
    report["checks"].append(name)


def announce_session(path):
    print(
        json.dumps(
            {
                "mode": "private_home_console_session",
                "session_file": str(path),
                "radio": "simulated",
                "hardware_rf_tested": False,
            }
        ),
        flush=True,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edge-binary", default=os.environ.get("GM_EDGE_BINARY"))
    parser.add_argument("--verify-binary", default=os.environ.get("GM_VERIFY_BINARY"))
    parser.add_argument("--hold-seconds", type=int, choices=range(301), default=0, metavar="0..300")
    parser.add_argument(
        "--console-checks", action="store_true", help="also verify console admission"
    )
    parser.add_argument("--report", type=Path, default=ROOT / "artifacts" / "home-pilot-lab.json")
    args = parser.parse_args(argv)
    report = {
        "schema": "genesismesh-radio-home-lab/v1",
        "status": "running",
        "recorded_at": datetime.now(UTC).isoformat(),
        "authority": "real_disposable_genesismesh",
        "control": "real_authenticated_loopback_http",
        "radio": "simulated_injected_meshtastic",
        "device_state": "simulated_process_memory; service restart is not a microcontroller reset",
        "hardware_rf_tested": False,
        "state": "private_temporary_linux_directory; never reused",
        "private_state_removed": None,
        "hold_seconds": args.hold_seconds,
        "console_checks_requested": args.console_checks,
        "checks": [],
    }
    started = time.monotonic()
    code = 0
    previous_umask = None
    private_root = None
    try:
        if platform.system() != "Linux":
            raise LabError("requires_linux_or_wsl")
        if not args.edge_binary or not args.verify_binary:
            raise LabError("explicit_test_binaries_required")
        if args.console_checks:
            try:
                importlib.import_module("starlette.testclient")
            except ImportError:
                raise LabError("console_extra_required") from None
        report["runtime"] = runtime_info(args.edge_binary, args.verify_binary)
        from home_pilot_scenario import home_pilot_scenarios

        from genesismesh_radio.provision import _private_filesystem

        previous_umask = os.umask(0o077)
        # Ignore inherited TMPDIR: the edge agent requires actual private Linux state.
        with tempfile.TemporaryDirectory(prefix="gm-home-pilot-", dir="/tmp") as directory:
            root = Path(directory)
            private_root = root
            root.chmod(0o700)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _private_filesystem(descriptor)
            finally:
                os.close(descriptor)
            home_pilot_scenarios(
                root,
                str(Path(args.edge_binary).resolve()),
                str(Path(args.verify_binary).resolve()),
                report,
                check,
                hold_seconds=args.hold_seconds,
                on_session=announce_session,
                console_checks=args.console_checks,
            )
        report["status"] = "passed"
    except KeyboardInterrupt:
        report["status"], report["error"] = "interrupted", "operator_interrupted"
        code = 130
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error) if isinstance(error, LabError) else type(error).__name__
        code = 1
    finally:
        if previous_umask is not None:
            os.umask(previous_umask)
        if private_root is not None:
            report["private_state_removed"] = not private_root.exists()
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        try:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        except OSError:
            report["status"], report["error"], code = "failed", "report_write_failed", 1
    summary = {"status": report["status"], "checks": len(report["checks"])}
    if code:
        summary["error"] = report["error"]
    print(json.dumps(summary))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
