"""CLI integration kept separate from direct radio ownership."""

from __future__ import annotations

import math
import os
import re
import signal
import threading
import time

from .control_client import ControlClient

CLIENT_ACTIONS = {"service-status", "service-health", "service-command", "service-result"}


def add_arguments(sub):
    provision = sub.add_parser("provision", help="generate a fresh private device bundle")
    provision.add_argument("--config", required=True)
    provision.add_argument("--output", required=True)
    for action in sorted(CLIENT_ACTIONS):
        command = sub.add_parser(action, help="contact the running local bridge service")
        command.add_argument("--url", default="http://127.0.0.1:17901")
        command.add_argument("--token-env", default="GM_RADIO_CONTROL_TOKEN")
        command.add_argument("--timeout", type=float, default=15)
        if action in {"service-command", "service-result"}:
            command.add_argument("--request-id", required=True)
        if action == "service-command":
            command.add_argument("--device-id", type=int, required=True)
            command.add_argument("--interval", type=int, required=True)
            command.add_argument("--ttl", type=int, default=60)


def token_from_environment(reference):
    if not isinstance(reference, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reference):
        raise ValueError("invalid_control_token_reference")
    return os.environ.get(reference, "")


def client_action(args):
    with ControlClient(
        args.url, token_from_environment(args.token_env), timeout=args.timeout
    ) as client:
        if args.action == "service-health":
            return client.health()
        if args.action == "service-status":
            return client.status()
        if args.action == "service-result":
            return client.result(args.request_id)
        return client.command(args.request_id, args.device_id, args.interval, args.ttl)


def serve(args, config, keys, emit):
    from .service import ControlService

    if not math.isfinite(args.seconds) or args.seconds < 0:
        raise ValueError("seconds_must_be_finite_and_nonnegative")
    stop = threading.Event()
    service = ControlService(
        config, keys, token_from_environment(args.token_env), host=args.host, port=args.port
    )
    previous = None
    if threading.current_thread() is threading.main_thread():
        previous = signal.signal(signal.SIGTERM, lambda *_: stop.set())
    started = time.monotonic()
    try:
        service.start()
        emit({"started": True, "url": f"http://{service.address[0]}:{service.address[1]}"})
        while not stop.wait(0.1):
            if not service.health()["alive"]:
                raise RuntimeError("service_owner_stopped")
            if args.seconds and time.monotonic() - started >= args.seconds:
                break
        return {"stopped": True}
    finally:
        try:
            service.close()
        finally:
            if previous is not None:
                signal.signal(signal.SIGTERM, previous)
