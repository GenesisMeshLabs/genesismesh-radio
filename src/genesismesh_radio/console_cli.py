"""Explicit private console administration and direct HTTPS serving."""

from __future__ import annotations

import argparse
import getpass
import json
import math
import os
import secrets
import sys
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .control_client import ControlClient


def bridge_session(path):
    from .console.store import private_database

    path = private_database(Path(path))
    if path.stat().st_size > 16384:
        raise ValueError("bridge_session_too_large")
    data = json.loads(path.read_text("utf-8"))
    if (
        not isinstance(data, dict)
        or data.get("schema") != "genesismesh-radio-home-session/v1"
        or data.get("authority") != "real_disposable_genesismesh"
        or data.get("hardware_rf_tested") is not False
    ):
        raise ValueError("invalid_bridge_session")
    expiry = datetime.fromisoformat(data["expires_at"])
    if expiry.tzinfo is None or expiry <= datetime.now(UTC):
        raise ValueError("bridge_session_expired")
    return data


def listen_host(settings, requested):
    """Separate browser origin from an explicit WSL NAT bind without trusting proxy headers."""
    from .console.app import ConsoleSettings

    parsed = urlsplit(settings.origin)
    if requested is None:
        return parsed.hostname
    # Reuse the same literal/private IPv4 and HTTPS-or-explicit-loopback rules.
    ConsoleSettings(f"{parsed.scheme}://{requested}:{parsed.port}", settings.development_loopback)
    return requested


@contextmanager
def demo_bridge():
    """Synthetic authority and RF, deliberately labelled; never opens a radio device."""
    from .adapters.base import Inbound
    from .bridge import Bridge
    from .config import Config, DeviceConfig, binding
    from .journal import Journal
    from .service import ControlService
    from .simulator import DeviceSimulator, LoopbackTransport, SimulationEdge

    with tempfile.TemporaryDirectory(prefix="gm-console-demo-") as name:
        root = Path(name)
        key, token = secrets.token_bytes(32), secrets.token_hex(32)
        config = Config(
            "home-console-demo",
            (DeviceConfig(1, "room-one", "simulated", "edge:home-pilot/room-one", "DEMO_KEY"),),
            root / "bridge.db",
        )
        keys = {1: key}
        Journal.initialize(config.state_path, binding(config, keys))

        @contextmanager
        def resources(config, keys):
            peer = DeviceSimulator(1, key, config.audience)
            adapter = LoopbackTransport({"room-one": peer})
            edge = SimulationEdge()
            with Journal(config.state_path, binding(config, keys)) as journal:
                bridge = Bridge(config, journal, edge, {"simulated": adapter}, keys=keys)
                original = bridge.run_once
                next_sample = 0

                def tick(timeout):
                    nonlocal next_sample
                    now = int(time.time())
                    if now >= next_sample:
                        adapter.incoming.put(Inbound("room-one", peer.telemetry(value=2250)))
                        next_sample = now + 2
                    return original(timeout)

                bridge.run_once = tick
                try:
                    yield bridge
                finally:
                    peer.close()

        with (
            ControlService(config, keys, token, port=0, resource_factory=resources) as service,
            ControlClient(f"http://127.0.0.1:{service.address[1]}", token) as client,
        ):
            yield client


def parser():
    result = argparse.ArgumentParser(description="GenesisMesh home radio operator console")
    sub = result.add_subparsers(dest="action", required=True)
    for name in ("init", "set-user", "revoke", "serve", "demo"):
        command = sub.add_parser(name)
        command.add_argument(
            "--state",
            type=Path,
            required=True,
            help="private operator SQLite file in an existing WSL/Linux 0700 directory",
        )
        if name in {"init", "set-user", "revoke"}:
            command.add_argument("--username", required=True)
        if name in {"init", "set-user"}:
            command.add_argument("--role", choices=["observer", "operator"], required=True)
        if name in {"serve", "demo"}:
            command.add_argument("--origin", default="http://127.0.0.1:17902")
            command.add_argument("--listen-host", help="explicit private IPv4 bind for WSL NAT")
            command.add_argument("--development-loopback", action="store_true")
            command.add_argument("--ssl-certfile", type=Path)
            command.add_argument("--ssl-keyfile", type=Path)
            command.add_argument(
                "--seconds",
                type=float,
                default=0,
                help="0 until interrupted; otherwise a bounded diagnostic run",
            )
        if name == "serve":
            command.add_argument("--control-url", default="http://127.0.0.1:17901")
            command.add_argument("--token-env", default="GM_RADIO_CONTROL_TOKEN")
            command.add_argument("--bridge-session", type=Path)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        from .console.store import OperatorStore, validate_user

        password = None
        if args.action in {"init", "set-user"}:
            password = getpass.getpass("New console password (16 to 128 characters): ")
            if password != getpass.getpass("Confirm password: "):
                raise ValueError("password_confirmation_failed")
            validate_user(args.username, password, args.role)
        with ExitStack() as stack:
            store = OperatorStore(args.state, create=args.action == "init")
            stack.callback(store.close)
            if args.action in {"init", "set-user"}:
                store.set_user(args.username, password, args.role)
                print(
                    json.dumps(
                        {
                            "operator_updated": args.username,
                            "role": args.role,
                            "identity_scope": "local_console_admission",
                        }
                    )
                )
                return 0
            if args.action == "revoke":
                store.revoke(args.username)
                print(json.dumps({"operator_disabled": args.username}))
                return 0
            import uvicorn

            from .console.app import ConsoleSettings, create_app

            if not math.isfinite(args.seconds) or not 0 <= args.seconds <= 86400:
                raise ValueError("invalid_console_duration")
            mode = "configured_bridge"
            if args.action == "demo":
                backend = stack.enter_context(demo_bridge())
                mode = "simulated_authority_and_radio"
            else:
                url, token = args.control_url, os.environ.get(args.token_env, "")
                if args.bridge_session:
                    session = bridge_session(args.bridge_session)
                    url, token = session["control_url"], session["control_token"]
                    mode = "real_authority_simulated_radio"
                backend = stack.enter_context(ControlClient(url, token))
            settings = ConsoleSettings(args.origin, args.development_loopback, mode)
            parsed = urlsplit(settings.origin)
            host = listen_host(settings, args.listen_host)
            if parsed.scheme == "https":
                if not args.ssl_certfile or not args.ssl_keyfile:
                    raise ValueError("https_requires_certificate_and_private_key")
                from .console.store import private_database

                private_database(args.ssl_keyfile)
            elif args.ssl_certfile or args.ssl_keyfile:
                raise ValueError("tls_files_require_https_origin")
            config = uvicorn.Config(
                create_app(settings, store, backend),
                host=host,
                port=parsed.port,
                ssl_certfile=str(args.ssl_certfile) if args.ssl_certfile else None,
                ssl_keyfile=str(args.ssl_keyfile) if args.ssl_keyfile else None,
                proxy_headers=False,
                forwarded_allow_ips="",
                access_log=False,
                server_header=False,
                limit_concurrency=32,
                timeout_keep_alive=3,
                timeout_graceful_shutdown=20,
                log_level="warning",
            )
            server = uvicorn.Server(config)
            if args.seconds:
                timer = threading.Timer(args.seconds, lambda: setattr(server, "should_exit", True))
                timer.daemon = True
                timer.start()
                stack.callback(timer.cancel)
            print(
                json.dumps(
                    {
                        "console_origin": settings.origin,
                        "mode": mode,
                        "hardware_rf_tested": False if mode != "configured_bridge" else None,
                        "identity_scope": "local_console_admission",
                    }
                ),
                flush=True,
            )
            server.run()
            return 0
    except Exception as exc:
        # Never render exception text: HTTP clients, paths and parsers may carry private details.
        print(
            json.dumps({"error": "console_operation_failed", "type": type(exc).__name__}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
