"""Local operator CLI; all keys are loaded from explicit environment references."""

from __future__ import annotations

import argparse
import json
import math
import secrets
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

from .bridge import Bridge
from .config import Config, DeviceConfig, binding, load_config, load_keys
from .journal import Journal
from .runtime import create_edge, create_transports, validate_runtime
from .simulator import DeviceSimulator, LoopbackTransport, SimulationEdge

_SAFE_ERROR_CODES = {
    "edge_invalid_identifier",
    "edge_invalid_deadline",
    "edge_http_error",
    "edge_response_too_large",
    "edge_transport_error",
    "edge_invalid_json",
    "edge_invalid_response",
    "edge_invalid_authorization",
    "edge_invalid_outcome_response",
}


def _validate_arguments(args, config):
    if args.action == "run" and (not math.isfinite(args.seconds) or args.seconds < 0):
        raise ValueError("seconds_must_be_finite_and_nonnegative")
    if args.action == "command":
        device = config.device(args.device_id)
        if not device.min_interval <= args.interval <= device.max_interval:
            raise ValueError("interval_outside_device_limits")
        if not 3 <= args.ttl <= 300:
            raise ValueError("command_ttl_must_be_3_to_300_seconds")
        if args.request_id is not None and str(uuid.UUID(args.request_id)) != args.request_id:
            raise ValueError("invalid_request_id")
        budget = min(
            item.max_payload for item in config.devices if item.transport == device.transport
        )
        if budget < 46:
            raise ValueError("transport_cannot_carry_command_outcome")


def _print(value):
    print(json.dumps(value, sort_keys=True, indent=2))


def demo():
    with tempfile.TemporaryDirectory(prefix="gm-radio-demo-") as temporary:
        key = secrets.token_bytes(32)
        device = DeviceConfig(1, "sensor-1", "simulated", "edge:demo/sensor-1", "DEMO_KEY")
        config = Config("demo.local", (device,), Path(temporary) / "bridge.db")
        keys = {1: key}
        identity = binding(config, keys)
        Journal.initialize(config.state_path, identity)
        peer = DeviceSimulator(1, key, config.audience)
        transport, edge = LoopbackTransport({device.route: peer}), SimulationEdge()
        try:
            with Journal(config.state_path, identity) as journal:
                bridge = Bridge(config, journal, edge, {device.transport: transport}, keys=keys)
                command = bridge.start_command(1, 60)
                bridge.run_once()
                result = journal.command(command["command_id"])
                return {
                    "mode": "simulation",
                    "authority": "simulated",
                    "hardware_tested": False,
                    "command": result,
                    "device_interval": peer.interval,
                    "reports": edge.reports,
                }
        finally:
            peer.close()


def parser():
    result = argparse.ArgumentParser(description="GenesisMesh LoRa and LoRaWAN bridge")
    sub = result.add_subparsers(dest="action", required=True)
    sub.add_parser("demo", help="run an explicitly simulated local workflow")
    for name in ("check-config", "init-state", "status", "run", "command"):
        command = sub.add_parser(name)
        command.add_argument("--config", required=True, type=Path)
        if name == "run":
            command.add_argument(
                "--seconds", type=float, default=0, help="0 means until interrupted"
            )
        if name == "command":
            command.add_argument("--device-id", type=int, required=True)
            command.add_argument("--interval", type=int, required=True)
            command.add_argument("--ttl", type=int, default=60)
            command.add_argument(
                "--request-id", help="reuse UUID to inspect a request without resend"
            )
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.action == "demo":
            _print(demo())
            return 0
        config = load_config(args.config)
        validate_runtime(config)
        _validate_arguments(args, config)
        keys = load_keys(config)
        identity = binding(config, keys)
        if args.action == "check-config":
            _print(
                {
                    "valid": True,
                    "audience": config.audience,
                    "devices": len(config.devices),
                    "transports": list(config.transports),
                    "state_exists": config.state_path.is_file(),
                }
            )
            return 0
        if args.action == "init-state":
            Journal.initialize(config.state_path, identity)
            _print({"initialized": True, "state_path": str(config.state_path)})
            return 0
        with ExitStack() as stack:
            journal = stack.enter_context(Journal(config.state_path, identity))
            if args.action == "status":
                _print({"commands": journal.commands(), "event_count": len(journal.events())})
                return 0
            edge = create_edge(config)
            stack.callback(edge.close)
            transports = create_transports(config, stack)
            bridge = Bridge(config, journal, edge, transports, keys=keys)
            started = time.monotonic()
            if args.action == "command":
                command = bridge.start_command(
                    args.device_id, args.interval, args.ttl, command_id=args.request_id
                )
                while time.monotonic() - started < args.ttl + 4:
                    bridge.run_once()
                    command = journal.command(command["command_id"])
                    if (
                        command["state"]
                        not in {
                            "authorizing",
                            "authorized",
                            "sending",
                            "dispatched",
                        }
                        and command["report_status"] != "pending"
                    ):
                        break
                _print(command)
                return (
                    0
                    if command["state"] == "confirmed" and command["report_status"] == "accepted"
                    else 2
                )
            while not args.seconds or time.monotonic() - started < args.seconds:
                bridge.run_once()
            _print(bridge.status())
            return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        # Dependency errors may contain broker credentials/URLs. Never print their
        # messages: sanitized type plus a narrow code is enough for the operator.
        code = getattr(exc, "code", None)
        _print(
            {
                "error": type(exc).__name__,
                "code": code
                if isinstance(code, str) and code in _SAFE_ERROR_CODES
                else "operation_failed",
                "detail": "Check configuration, local service status, and the private journal.",
            }
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
