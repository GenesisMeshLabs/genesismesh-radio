"""Durable replay counters and explicit command/evidence states."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class JournalError(RuntimeError):
    pass


class Journal:
    @classmethod
    def initialize(cls, path: str | Path, config_binding: str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        db = sqlite3.connect(path)
        try:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE counters (device_id INTEGER PRIMARY KEY,
                  rx TEXT NOT NULL DEFAULT '0', rx_digest TEXT NOT NULL DEFAULT '',
                  tx TEXT NOT NULL DEFAULT '0');
                CREATE TABLE commands (
                  command_id TEXT PRIMARY KEY, device_id INTEGER NOT NULL,
                  counter TEXT NOT NULL, interval_seconds INTEGER NOT NULL,
                  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                  state TEXT NOT NULL, authorization_id TEXT, authority TEXT,
                  frame_digest TEXT, result_json TEXT, report_status TEXT NOT NULL DEFAULT 'none',
                  report_attempts INTEGER NOT NULL DEFAULT 0,
                  next_report_at INTEGER NOT NULL DEFAULT 0,
                  UNIQUE(device_id, counter));
                CREATE TABLE events (
                  event_id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL,
                  counter TEXT NOT NULL, kind TEXT NOT NULL, frame_digest TEXT NOT NULL,
                  received_at INTEGER NOT NULL, frame_hex TEXT NOT NULL, details_json TEXT NOT NULL,
                  UNIQUE(device_id, counter));
                CREATE INDEX command_work ON commands(state, report_status);
                CREATE INDEX command_reports ON commands(report_status);
            """)
            db.executemany(
                "INSERT INTO meta VALUES (?, ?)",
                [("version", "1"), ("binding", config_binding), ("last_time", "0")],
            )
            db.commit()
        finally:
            db.close()

    def __init__(
        self, path: str | Path, config_binding: str, *, max_events=100_000, max_commands=10_000
    ):
        if any(type(limit) is not int or limit < 1 for limit in (max_events, max_commands)):
            raise JournalError("invalid_journal_capacity")
        self.max_events, self.max_commands = max_events, max_commands
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise JournalError("state_missing_or_symlink: explicitly provision state first")
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise JournalError("state_permissions_must_be_private")
        self._lock = path.with_suffix(path.suffix + ".lock").open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self._lock.seek(0)
                if not self._lock.read(1):
                    self._lock.write(b"\0")
                    self._lock.flush()
                self._lock.seek(0)
                msvcrt.locking(self._lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._lock.close()
            raise JournalError("state_already_in_use") from exc
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            metadata = dict(self.db.execute("SELECT name,value FROM meta"))
            if metadata.get("version") != "1" or metadata.get("binding") != config_binding:
                raise JournalError("state_identity_binding_mismatch")
            self.config_binding = config_binding
            if self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise JournalError("state_corrupt")
        except Exception:
            self.close()
            raise

    def close(self):
        self.db.close()
        self._lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def observe_time(self, now: int):
        if type(now) is not int or now < 0:
            raise JournalError("invalid_clock")
        with self.transaction():
            previous = int(
                self.db.execute("SELECT value FROM meta WHERE name='last_time'").fetchone()[0]
            )
            if now < previous:
                raise JournalError("clock_rollback")
            self.db.execute("UPDATE meta SET value=? WHERE name='last_time'", (str(now),))

    @staticmethod
    def _command(row):
        if row is None:
            return None
        result = dict(row)
        result["counter"] = int(result["counter"])
        result["result"] = json.loads(result.pop("result_json") or "null")
        return result

    def command(self, command_id: str):
        return self._command(
            self.db.execute("SELECT * FROM commands WHERE command_id=?", (command_id,)).fetchone()
        )

    def command_by_counter(self, device_id: int, counter: int):
        return self._command(
            self.db.execute(
                "SELECT * FROM commands WHERE device_id=? AND counter=?", (device_id, str(counter))
            ).fetchone()
        )

    def commands(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise JournalError("invalid_page_size")
        rows = self.db.execute("SELECT * FROM commands ORDER BY rowid DESC LIMIT ?", (limit,))
        return list(reversed([self._command(row) for row in rows]))

    def pending_commands(self):
        rows = self.db.execute("""SELECT * FROM commands WHERE
            state IN ('authorizing','authorized','sending','dispatched') OR report_status='pending'
            ORDER BY rowid""")
        return [self._command(row) for row in rows]

    def event_count(self):
        return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def command_count(self):
        return self.db.execute("SELECT COUNT(*) FROM commands").fetchone()[0]

    def reserve_command(self, command_id, device_id, interval_seconds, now, expires_at):
        with self.transaction():
            if self.command_count() >= self.max_commands:
                raise JournalError("command_capacity_reached")
            self.db.execute("INSERT OR IGNORE INTO counters(device_id) VALUES (?)", (device_id,))
            counter = (
                int(
                    self.db.execute(
                        "SELECT tx FROM counters WHERE device_id=?", (device_id,)
                    ).fetchone()[0]
                )
                + 1
            )
            if counter >= 2**64:
                raise JournalError("counter_exhausted_reprovision_required")
            self.db.execute("UPDATE counters SET tx=? WHERE device_id=?", (str(counter), device_id))
            self.db.execute(
                """INSERT INTO commands
                (command_id, device_id, counter, interval_seconds, created_at, expires_at, state)
                VALUES(?,?,?,?,?,?,'authorizing')""",
                (command_id, device_id, str(counter), interval_seconds, now, expires_at),
            )
        return self.command(command_id)

    def update_command(self, command_id: str, **changes):
        allowed = {
            "state",
            "authorization_id",
            "authority",
            "expires_at",
            "frame_digest",
            "result",
            "report_status",
            "report_attempts",
            "next_report_at",
        }
        if not changes or changes.keys() - allowed:
            raise JournalError("invalid_command_update")
        if "result" in changes:
            changes["result_json"] = json.dumps(changes.pop("result"), sort_keys=True)
        sql = "UPDATE commands SET " + ",".join(f"{name}=?" for name in changes)
        with self.transaction():
            cursor = self.db.execute(sql + " WHERE command_id=?", (*changes.values(), command_id))
            if cursor.rowcount != 1:
                raise JournalError("unknown_command")
        return self.command(command_id)

    def accept_event(
        self, *, device_id, counter, digest, kind, now, raw, details, command_update=None
    ):
        with self.transaction():
            self.db.execute("INSERT OR IGNORE INTO counters(device_id) VALUES (?)", (device_id,))
            previous = self.db.execute(
                "SELECT rx,rx_digest FROM counters WHERE device_id=?", (device_id,)
            ).fetchone()
            if counter == int(previous["rx"]) and digest == previous["rx_digest"]:
                return {"duplicate": True, "device_id": device_id, "counter": counter}
            if counter <= int(previous["rx"]):
                raise JournalError("replayed_or_reordered_frame")
            if self.event_count() >= self.max_events:
                raise JournalError("event_capacity_reached")
            self.db.execute(
                "UPDATE counters SET rx=?,rx_digest=? WHERE device_id=?",
                (str(counter), digest, device_id),
            )
            cursor = self.db.execute(
                """INSERT INTO events
                (device_id,counter,kind,frame_digest,received_at,frame_hex,details_json)
                VALUES(?,?,?,?,?,?,?)""",
                (device_id, str(counter), kind, digest, now, raw.hex(), json.dumps(details)),
            )
            if command_update:
                command_id, state, result = command_update
                self.db.execute(
                    """UPDATE commands SET state=?,result_json=?,report_status='pending'
                    WHERE command_id=?""",
                    (state, json.dumps(result), command_id),
                )
            return {
                "event_id": cursor.lastrowid,
                "duplicate": False,
                "device_id": device_id,
                "counter": counter,
                "kind": kind,
                "frame_digest": digest,
                "details": details,
            }

    def events(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise JournalError("invalid_page_size")
        rows = []
        for row in self.db.execute("SELECT * FROM events ORDER BY event_id DESC LIMIT ?", (limit,)):
            event = dict(row)
            event["counter"] = int(event["counter"])
            event["details"] = json.loads(event.pop("details_json"))
            rows.append(event)
        return list(reversed(rows))

    def latest_telemetry(self):
        """At most 100 recent device observations; omit raw radio frames."""
        rows = self.db.execute("""
            SELECT device_id,received_at,details_json FROM events
            WHERE event_id IN (SELECT MAX(event_id) FROM events
              WHERE kind='telemetry' GROUP BY device_id)
            ORDER BY event_id DESC LIMIT 100
        """)
        return [
            {
                "device_id": row["device_id"],
                "received_at": row["received_at"],
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]
