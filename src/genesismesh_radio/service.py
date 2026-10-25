"""Continuous bridge ownership and a bounded, authenticated local control API."""

from __future__ import annotations

import copy
import math
import queue
import threading
import time
from concurrent.futures import Future, TimeoutError
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass

from .bridge import Bridge, BridgeError
from .config import Config, ConfigError, binding
from .journal import Journal, JournalError
from .local_http import LocalHTTPServer, validate_endpoint
from .runtime import create_edge, create_transports, validate_runtime


class ServiceError(RuntimeError):
    """Sanitized local-service startup or shutdown failure."""


@contextmanager
def bridge_resources(config, keys):
    """Called inside the owner thread, including every resource's teardown."""
    validate_runtime(config)
    with ExitStack() as stack:
        journal = stack.enter_context(Journal(config.state_path, binding(config, keys)))
        edge = create_edge(config)
        stack.callback(edge.close)
        transports = create_transports(config, stack)
        yield Bridge(config, journal, edge, transports, keys=keys)


@dataclass(frozen=True)
class _Work:
    operation: str
    argument: object
    future: Future


class ControlService:
    def __init__(
        self,
        config: Config,
        keys: dict[int, bytes],
        token: str,
        *,
        host="127.0.0.1",
        port=17901,
        resource_factory=bridge_resources,
        mailbox_size=16,
        operation_timeout=15.0,
        request_timeout=2.0,
        tick_interval=0.05,
        stale_after=30.0,
        startup_timeout=30.0,
    ):
        validate_endpoint(host, port, token)
        binding(config, keys)
        if any(token == key.hex() for key in keys.values()):
            raise ValueError("service_token_must_differ_from_device_keys")
        if type(mailbox_size) is not int or not 1 <= mailbox_size <= 16:
            raise ValueError("invalid_mailbox_size")
        for value, maximum in (
            (operation_timeout, 15),
            (request_timeout, 10),
            (tick_interval, 1),
            (stale_after, 300),
            (startup_timeout, 300),
        ):
            if (
                type(value) not in {int, float}
                or not math.isfinite(value)
                or not 0 < value <= maximum
            ):
                raise ValueError("invalid_service_timeout")
        self._config, self._keys = copy.deepcopy(config), dict(keys)
        self._host, self._port, self._token = host, port, token
        self._factory, self._operation_timeout = resource_factory, operation_timeout
        self._request_timeout, self._tick_interval = request_timeout, tick_interval
        self._stale_after, self._startup_timeout = stale_after, startup_timeout
        self._mailbox = queue.Queue(maxsize=mailbox_size)
        self._command_work = None
        self._lock = threading.Lock()
        self._stop, self._started = threading.Event(), threading.Event()
        self._owner = self._http_thread = self._http = None
        self._state, self._last_progress = "new", None

    @property
    def address(self):
        if self._http is None:
            raise ServiceError("service_not_started")
        return self._host, self._http.server_address[1]

    def health(self):
        with self._lock:
            state, last_progress = self._state, self._last_progress
        alive = self._owner is not None and self._owner.is_alive() and state != "failed"
        age = None if last_progress is None else max(0, time.monotonic() - last_progress)
        stale = age is not None and age > self._stale_after
        return {
            "alive": alive,
            "ready": alive and state == "running" and not stale and not self._stop.is_set(),
            "state": state,
            "owner_stale": stale,
            "last_progress_seconds_ago": None if age is None else round(age, 3),
            "queue_depth": self._mailbox.qsize(),
            "scope": "local_bridge_process_only",
        }

    def start(self):
        with self._lock:
            if self._state != "new":
                raise ServiceError("service_already_started")
            self._state = "starting"
        self._owner = threading.Thread(target=self._own, name="gm-radio-owner", daemon=True)
        self._owner.start()
        if not self._started.wait(self._startup_timeout) or not self.health()["ready"]:
            self.close()
            raise ServiceError("service_start_failed")
        try:
            self._http = LocalHTTPServer(
                self._host,
                self._port,
                self._token,
                self._dispatch,
                request_timeout=self._request_timeout,
            )
            self._http_thread = threading.Thread(
                target=self._http.serve_forever,
                kwargs={"poll_interval": 0.05},
                name="gm-radio-http",
                daemon=True,
            )
            self._http_thread.start()
        except Exception:
            self.close()
            raise ServiceError("service_listen_failed") from None
        return self

    def close(self):
        with self._lock:
            self._stop.set()
            if self._state != "failed":
                self._state = "stopping"
        if self._http is not None:
            if self._http_thread is not None and self._http_thread.is_alive():
                self._http.shutdown()
                self._http_thread.join(timeout=1)
            self._http.server_close()
        if self._owner is not None:
            self._owner.join(timeout=30)
            if self._owner.is_alive():
                raise ServiceError("service_shutdown_pending")
        with self._lock:
            if self._state != "failed":
                self._state = "stopped"

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()

    def _dispatch(self, operation, argument):
        if operation == "health":
            health = self.health()
            return (200 if health["ready"] else 503), health
        with self._lock:
            if self._state != "running" or self._stop.is_set():
                return 503, {"code": "service_unavailable"}
            existing = self._command_work if operation == "command" else None
            if existing is not None:
                if existing.argument != argument:
                    code = (
                        "command_id_conflict"
                        if existing.argument["command_id"] == argument["command_id"]
                        else "another_command_or_report_is_pending"
                    )
                    return 409, {"code": code}
                future = existing.future
            else:
                future = Future()
                work = _Work(operation, argument, future)
                try:
                    self._mailbox.put_nowait(work)
                except queue.Full:
                    return 503, {"code": "mailbox_full"}
                if operation == "command":
                    self._command_work = work
        try:
            return future.result(timeout=self._operation_timeout)
        except TimeoutError:
            # Never cancel: work may already have reserved durable intent or sent a frame.
            payload = {"code": "operation_unconfirmed"}
            if operation == "command":
                payload["command_id"] = argument["command_id"]
            return 504, payload

    def _complete(self, work, result):
        # Only the owner releases the command slot. A timed-out HTTP caller cannot.
        with self._lock:
            if self._command_work is work:
                self._command_work = None
            work.future.set_result(result)

    def _progress(self):
        with self._lock:
            self._last_progress = time.monotonic()

    @staticmethod
    def _execute(bridge, work):
        try:
            if work.operation == "status":
                return 200, bridge.status()
            if work.operation == "lookup":
                result = bridge.journal.command(work.argument)
                return (200, result) if result is not None else (404, {"code": "command_not_found"})
            if work.operation == "command":
                return 202, bridge.start_command(**work.argument)
            return 404, {"code": "not_found"}
        except ConfigError:
            return 400, {"code": "invalid_command"}
        except BridgeError as exc:
            if str(exc) in {"command_id_conflict", "another_command_or_report_is_pending"}:
                return 409, {"code": str(exc)}
            if str(exc) in {
                "invalid_command_id",
                "interval_outside_device_limits",
                "command_ttl_must_be_3_to_300_seconds",
                "transport_payload_budget_too_small",
            }:
                return 400, {"code": str(exc)}
            raise
        except JournalError:
            # Capacity, corruption, time rollback, and storage failures stop this owner.
            raise

    def _own(self):
        active = None
        try:
            with self._factory(self._config, self._keys) as bridge:
                with self._lock:
                    self._state = "running"
                    self._last_progress = time.monotonic()
                self._started.set()
                while not self._stop.is_set():
                    try:
                        active = self._mailbox.get_nowait()
                    except queue.Empty:
                        active = None
                    if active is not None:
                        # Linearize owner admission against close(). A dequeued request
                        # is not active until it passes this check under the same lock.
                        with self._lock:
                            stopping = self._stop.is_set()
                        if stopping:
                            self._complete(active, (503, {"code": "service_unavailable"}))
                            active = None
                            break
                        self._complete(active, self._execute(bridge, active))
                        active = None
                        self._progress()
                    if not self._stop.is_set():
                        bridge.run_once(self._tick_interval)
                        self._progress()
        except Exception:
            with self._lock:
                self._state = "failed"
            if active is not None:
                response = {"code": "operation_unconfirmed"}
                if active.operation == "command":
                    response["command_id"] = active.argument["command_id"]
                self._complete(active, (504, response))
        finally:
            self._stop.set()
            self._started.set()
            while True:
                try:
                    pending = self._mailbox.get_nowait()
                except queue.Empty:
                    break
                self._complete(pending, (503, {"code": "service_unavailable"}))
