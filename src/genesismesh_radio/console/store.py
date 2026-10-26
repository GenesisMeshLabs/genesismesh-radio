"""Private operator records, bounded opaque sessions and durable submission ownership."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path

from ..provision import _directory, _private_filesystem, _private_platform


class AdmissionError(ValueError):
    """Non-secret console refusal."""


def _password(value):
    if not isinstance(value, str) or not 16 <= len(value) <= 128:
        raise AdmissionError("password_requires_16_to_128_characters")
    try:
        return value.encode("utf-8")
    except UnicodeError:
        raise AdmissionError("invalid_password_encoding") from None


def _hash(value, salt):
    # Fixed OWASP scrypt profile; parameters cannot be supplied by a client or DB row.
    return hashlib.scrypt(value, salt=salt, n=32768, r=8, p=3, maxmem=64 * 1024 * 1024)


def validate_user(username, password, role):
    """Validate administration input before opening or creating any private state."""
    if not isinstance(username, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", username):
        raise AdmissionError("invalid_username")
    if role not in {"observer", "operator"}:
        raise AdmissionError("invalid_local_role")
    return _password(password)


def private_database(path: Path, *, create=False):
    """Require an owned 0700 POSIX directory on a filesystem enforcing permissions."""
    _private_platform()
    path = path.absolute()
    parent = _directory(path.parent)
    try:
        _private_filesystem(parent)
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise AdmissionError("console_directory_requires_owner_mode_0700")
        flags = os.O_RDWR | os.O_NOFOLLOW
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        fd = os.open(path.name, flags, 0o600, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise AdmissionError("console_database_requires_private_regular_file")
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    return path


@dataclass(frozen=True)
class Session:
    digest: str
    username: str
    csrf: str
    created: float
    verifier: bytes


class OperatorStore:
    """Sessions intentionally expire at console restart; command intent does not."""

    def __init__(self, path=None, *, create=False, clock=time.monotonic, lifetime=1800):
        if type(lifetime) is not int or not 1 <= lifetime <= 3600:
            raise AdmissionError("invalid_session_lifetime")
        database = ":memory:" if path is None else str(private_database(Path(path), create=create))
        self._db = sqlite3.connect(database, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
              username TEXT PRIMARY KEY, salt BLOB NOT NULL, verifier BLOB NOT NULL,
              role TEXT NOT NULL, enabled INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS submissions (
              command_id TEXT PRIMARY KEY, username TEXT NOT NULL, body TEXT NOT NULL);
        """)
        self._lock = threading.RLock()
        self._hash_slots = threading.BoundedSemaphore(2)
        self._sessions = {}
        self._attempts = OrderedDict()
        self._global_attempts = deque(maxlen=60)
        self._clock, self._lifetime = clock, lifetime
        self._last_clock = clock()
        self._dummy_salt = secrets.token_bytes(16)
        self._dummy_hash = _hash(secrets.token_bytes(32), self._dummy_salt)

    def close(self):
        with self._lock:
            self._sessions.clear()
            self._db.close()

    def _now(self):
        now = self._clock()
        if now < self._last_clock:
            self._sessions.clear()
            raise AdmissionError("console_clock_regressed")
        self._last_clock = now
        return now

    def set_user(self, username, password, role):
        encoded = validate_user(username, password, role)
        salt = secrets.token_bytes(16)
        verifier = _hash(encoded, salt)
        with self._lock:
            if (
                not self._db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
                and self._db.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= 32
            ):
                raise AdmissionError("operator_capacity_reached")
            self._db.execute(
                "INSERT INTO users VALUES (?,?,?,?,1) ON CONFLICT(username) DO UPDATE SET "
                "salt=excluded.salt, verifier=excluded.verifier, role=excluded.role, enabled=1",
                (username, salt, verifier, role),
            )
            self._db.commit()
            self._revoke_sessions(username)

    def _revoke_sessions(self, username):
        self._sessions = {k: v for k, v in self._sessions.items() if v.username != username}

    def revoke(self, username):
        with self._lock:
            self._db.execute("UPDATE users SET enabled=0 WHERE username=?", (username,))
            self._db.commit()
            self._revoke_sessions(username)

    def _prune(self, now):
        self._sessions = {
            key: session
            for key, session in self._sessions.items()
            if 0 <= now - session.created < self._lifetime
        }

    def login(self, username, password, remote, previous=None):
        # Rate and password work are bounded even for changing or nonexistent user names.
        with self._lock:
            now = self._now()
            self._prune(now)
            for attempts in (self._global_attempts, self._attempts.get(remote, deque())):
                while attempts and attempts[0] <= now - 60:
                    attempts.popleft()
            if len(self._global_attempts) >= 60:
                raise AdmissionError("login_rate_limited")
            if remote not in self._attempts:
                if len(self._attempts) >= 256:
                    self._attempts.popitem(last=False)
                self._attempts[remote] = deque(maxlen=5)
            attempts = self._attempts[remote]
            if len(attempts) >= 5:
                raise AdmissionError("login_rate_limited")
            attempts.append(now)
            self._global_attempts.append(now)
            row = self._db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not self._hash_slots.acquire(blocking=False):
            raise AdmissionError("login_busy")
        try:
            supplied = _password(password)
            salt = row["salt"] if row else self._dummy_salt
            expected = row["verifier"] if row else self._dummy_hash
            valid = hmac.compare_digest(_hash(supplied, salt), expected)
        except AdmissionError:
            raise AdmissionError("login_refused") from None
        finally:
            self._hash_slots.release()
        with self._lock:
            current = self._db.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
            if (
                not valid
                or row is None
                or not row["enabled"]
                or current is None
                or dict(row) != dict(current)
            ):
                raise AdmissionError("login_refused")
            self._prune(self._now())
            if len(self._sessions) >= 128:
                raise AdmissionError("session_capacity_reached")
            if previous:
                self.logout(previous)
            token = secrets.token_hex(32)
            session = Session(
                hashlib.sha256(token.encode()).hexdigest(),
                username,
                secrets.token_hex(32),
                self._now(),
                bytes(row["verifier"]),
            )
            self._sessions[session.digest] = session
            return token, session

    def authenticate(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise AdmissionError("authentication_required")
        with self._lock:
            now = self._now()
            self._prune(now)
            session = self._sessions.get(hashlib.sha256(token.encode()).hexdigest())
            row = (
                None
                if session is None
                else self._db.execute(
                    "SELECT role,enabled,verifier FROM users WHERE username=?", (session.username,)
                ).fetchone()
            )
            if (
                session is None
                or row is None
                or not row["enabled"]
                or not hmac.compare_digest(session.verifier, row["verifier"])
            ):
                raise AdmissionError("authentication_required")
            return session, row["role"]

    def logout(self, token):
        with self._lock:
            self._sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)

    def reserve(self, session, body):
        """Reserve before effects. Existing intent permits lookup only, including after crash."""
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._prune(self._now())
            row = self._db.execute(
                "SELECT * FROM users WHERE username=?", (session.username,)
            ).fetchone()
            if (
                self._sessions.get(session.digest) != session
                or row is None
                or not row["enabled"]
                or row["role"] != "operator"
                or not hmac.compare_digest(session.verifier, row["verifier"])
            ):
                raise AdmissionError("operator_permission_required")
            existing = self._db.execute(
                "SELECT username,body FROM submissions WHERE command_id=?", (body["command_id"],)
            ).fetchone()
            if existing:
                if existing["username"] != session.username or existing["body"] != canonical:
                    raise AdmissionError("command_id_conflict")
                return False
            if self._db.execute("SELECT COUNT(*) FROM submissions").fetchone()[0] >= 10000:
                raise AdmissionError("submission_capacity_reached")
            self._db.execute(
                "INSERT INTO submissions VALUES (?,?,?)",
                (body["command_id"], session.username, canonical),
            )
            self._db.commit()
            return True
