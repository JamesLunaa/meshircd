"""Durable state, in SQLite.

The learning version of this server kept everything in memory, so a restart
silently destroyed every channel topic, mode, ban and operator grant on the
network. That is the single biggest thing separating "it runs" from "people
can rely on it", so state that an operator deliberately set is written here
and restored at startup.

What is *not* persisted: who is currently connected, which nick is in use,
and channel membership. Those describe live connections, and a connection
does not survive a restart no matter what we write down.

Access rules:

- One connection, opened with ``check_same_thread=False`` and guarded by a
  lock, because every call is funnelled through ``asyncio.to_thread``.
  SQLite writes are fast but they are *blocking*, and the whole design of
  this server is that nothing blocking runs on the event loop.
- WAL mode, so a reader never blocks the writer and an unclean shutdown
  recovers instead of corrupting.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
import time

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Accounts are identified case-insensitively but displayed as registered.
CREATE TABLE IF NOT EXISTS accounts (
    name_lower    TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    salt          TEXT NOT NULL,
    hash          TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER,
    locked        INTEGER NOT NULL DEFAULT 0
);

-- CertFP: a TLS client certificate fingerprint that authenticates as this
-- account without a password.
CREATE TABLE IF NOT EXISTS account_fingerprints (
    fingerprint TEXT PRIMARY KEY,
    name_lower  TEXT NOT NULL REFERENCES accounts(name_lower) ON DELETE CASCADE,
    added_at    INTEGER NOT NULL
);

-- Channel state an operator deliberately set. Membership is not stored.
CREATE TABLE IF NOT EXISTS channels (
    name_lower   TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    topic        TEXT,
    topic_setter TEXT,
    topic_time   INTEGER,
    modes        TEXT NOT NULL DEFAULT '',
    key          TEXT,
    user_limit   INTEGER,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS channel_lists (
    name_lower TEXT NOT NULL REFERENCES channels(name_lower) ON DELETE CASCADE,
    kind       TEXT NOT NULL,          -- 'b' ban, 'e' exempt, 'I' invex
    mask       TEXT NOT NULL,
    setter     TEXT NOT NULL DEFAULT '',
    set_at     INTEGER NOT NULL,
    PRIMARY KEY (name_lower, kind, mask)
);

-- Persistent operator status, keyed by *account* rather than nick: a nick
-- is transient, an account is the thing that can still be recognised after
-- a reconnect.
CREATE TABLE IF NOT EXISTS channel_access (
    name_lower TEXT NOT NULL REFERENCES channels(name_lower) ON DELETE CASCADE,
    account    TEXT NOT NULL,
    level      TEXT NOT NULL,          -- 'o' op, 'v' voice
    PRIMARY KEY (name_lower, account)
);

-- Server-wide bans. 'K' matches user@host, 'D' matches an IP or CIDR and
-- is enforced before registration.
CREATE TABLE IF NOT EXISTS server_bans (
    kind       TEXT NOT NULL,
    mask       TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    setter     TEXT NOT NULL DEFAULT '',
    set_at     INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (kind, mask)
);

CREATE INDEX IF NOT EXISTS idx_channels_last_used ON channels(last_used_at);
CREATE INDEX IF NOT EXISTS idx_bans_expiry ON server_bans(expires_at);
"""


class Storage:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        # The database holds password hashes; it must not be world readable.
        # Set the mode before SQLite creates the file where we can.
        new_file = not os.path.exists(path)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        if new_file:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA busy_timeout=5000")
        try:
            self._migrate()
        except Exception:
            # A database we refuse to use must not leave its handle open;
            # the caller is about to abort startup.
            self._db.close()
            raise

    # --- plumbing ------------------------------------------------------

    def _migrate(self):
        with self._lock:
            self._db.executescript(_SCHEMA)
            row = self._db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            current = int(row["value"]) if row else 0
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database {self.path} has schema version {current}, "
                    f"newer than this build understands ({SCHEMA_VERSION}). "
                    "Downgrading would lose data; refusing to start."
                )
            self._db.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )

    def _execute(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._db.execute(sql, params)

    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    def close(self):
        with self._lock:
            self._db.close()

    # Async wrappers. Every caller on the event loop uses these; the
    # synchronous methods exist for startup, shutdown and the CLI.
    async def run(self, func, *args):
        return await asyncio.to_thread(func, *args)

    # --- accounts ------------------------------------------------------

    def get_account(self, name_lower: str) -> sqlite3.Row | None:
        rows = self._query("SELECT * FROM accounts WHERE name_lower=?", (name_lower,))
        return rows[0] if rows else None

    def create_account(self, name: str, name_lower: str, salt: str, digest: str):
        self._execute(
            "INSERT INTO accounts(name_lower, name, salt, hash, created_at) VALUES(?,?,?,?,?)",
            (name_lower, name, salt, digest, int(time.time())),
        )

    def delete_account(self, name_lower: str) -> bool:
        cursor = self._execute("DELETE FROM accounts WHERE name_lower=?", (name_lower,))
        return cursor.rowcount > 0

    def set_account_password(self, name_lower: str, salt: str, digest: str) -> bool:
        cursor = self._execute(
            "UPDATE accounts SET salt=?, hash=? WHERE name_lower=?", (salt, digest, name_lower)
        )
        return cursor.rowcount > 0

    def set_account_locked(self, name_lower: str, locked: bool) -> bool:
        cursor = self._execute(
            "UPDATE accounts SET locked=? WHERE name_lower=?", (1 if locked else 0, name_lower)
        )
        return cursor.rowcount > 0

    def touch_account_login(self, name_lower: str):
        self._execute(
            "UPDATE accounts SET last_login_at=? WHERE name_lower=?", (int(time.time()), name_lower)
        )

    def list_accounts(self) -> list[sqlite3.Row]:
        return self._query("SELECT * FROM accounts ORDER BY name_lower")

    # --- CertFP --------------------------------------------------------

    def add_fingerprint(self, fingerprint: str, name_lower: str):
        self._execute(
            "INSERT OR REPLACE INTO account_fingerprints(fingerprint, name_lower, added_at) "
            "VALUES(?,?,?)",
            (fingerprint.lower(), name_lower, int(time.time())),
        )

    def remove_fingerprint(self, fingerprint: str) -> bool:
        cursor = self._execute(
            "DELETE FROM account_fingerprints WHERE fingerprint=?", (fingerprint.lower(),)
        )
        return cursor.rowcount > 0

    def account_for_fingerprint(self, fingerprint: str) -> sqlite3.Row | None:
        rows = self._query(
            "SELECT a.* FROM accounts a JOIN account_fingerprints f "
            "ON a.name_lower = f.name_lower WHERE f.fingerprint=?",
            (fingerprint.lower(),),
        )
        return rows[0] if rows else None

    def list_fingerprints(self, name_lower: str) -> list[str]:
        return [
            r["fingerprint"]
            for r in self._query(
                "SELECT fingerprint FROM account_fingerprints WHERE name_lower=? ORDER BY added_at",
                (name_lower,),
            )
        ]

    # --- channels ------------------------------------------------------

    def save_channel(self, state: dict):
        now = int(time.time())
        self._execute(
            "INSERT INTO channels(name_lower, name, topic, topic_setter, topic_time, "
            "modes, key, user_limit, created_at, last_used_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(name_lower) DO UPDATE SET name=excluded.name, topic=excluded.topic, "
            "topic_setter=excluded.topic_setter, topic_time=excluded.topic_time, "
            "modes=excluded.modes, key=excluded.key, user_limit=excluded.user_limit, "
            "last_used_at=excluded.last_used_at",
            (
                state["name_lower"], state["name"], state.get("topic"),
                state.get("topic_setter"), state.get("topic_time"),
                state.get("modes", ""), state.get("key"), state.get("user_limit"),
                state.get("created_at", now), now,
            ),
        )

    def forget_channel(self, name_lower: str):
        self._execute("DELETE FROM channels WHERE name_lower=?", (name_lower,))

    def load_channels(self) -> list[dict]:
        out = []
        for row in self._query("SELECT * FROM channels"):
            entry = dict(row)
            entry["lists"] = {}
            for item in self._query(
                "SELECT kind, mask, setter, set_at FROM channel_lists WHERE name_lower=?",
                (row["name_lower"],),
            ):
                entry["lists"].setdefault(item["kind"], []).append(dict(item))
            entry["access"] = {
                a["account"]: a["level"]
                for a in self._query(
                    "SELECT account, level FROM channel_access WHERE name_lower=?",
                    (row["name_lower"],),
                )
            }
            out.append(entry)
        return out

    def add_channel_list_entry(self, name_lower: str, kind: str, mask: str, setter: str):
        self._execute(
            "INSERT OR REPLACE INTO channel_lists(name_lower, kind, mask, setter, set_at) "
            "VALUES(?,?,?,?,?)",
            (name_lower, kind, mask, setter, int(time.time())),
        )

    def remove_channel_list_entry(self, name_lower: str, kind: str, mask: str):
        self._execute(
            "DELETE FROM channel_lists WHERE name_lower=? AND kind=? AND mask=?",
            (name_lower, kind, mask),
        )

    def set_channel_access(self, name_lower: str, account: str, level: str):
        self._execute(
            "INSERT OR REPLACE INTO channel_access(name_lower, account, level) VALUES(?,?,?)",
            (name_lower, account, level),
        )

    def clear_channel_access(self, name_lower: str, account: str):
        self._execute(
            "DELETE FROM channel_access WHERE name_lower=? AND account=?", (name_lower, account)
        )

    def prune_channels(self, older_than_seconds: int) -> int:
        """Drop channels nobody has used in a long time.

        Without this, every one-off channel anyone ever created would be
        stored forever -- an unbounded table fed by unauthenticated users,
        which is a resource-exhaustion bug with extra steps.
        """
        cutoff = int(time.time()) - older_than_seconds
        cursor = self._execute("DELETE FROM channels WHERE last_used_at < ?", (cutoff,))
        return cursor.rowcount

    # --- server bans ---------------------------------------------------

    def add_server_ban(
        self, kind: str, mask: str, reason: str, setter: str, expires_at: int | None
    ):
        self._execute(
            "INSERT OR REPLACE INTO server_bans(kind, mask, reason, setter, set_at, expires_at) "
            "VALUES(?,?,?,?,?,?)",
            (kind, mask, reason, setter, int(time.time()), expires_at),
        )

    def remove_server_ban(self, kind: str, mask: str) -> bool:
        cursor = self._execute(
            "DELETE FROM server_bans WHERE kind=? AND mask=?", (kind, mask)
        )
        return cursor.rowcount > 0

    def load_server_bans(self) -> list[dict]:
        now = int(time.time())
        self._execute("DELETE FROM server_bans WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        return [dict(r) for r in self._query("SELECT * FROM server_bans")]

    # --- diagnostics ---------------------------------------------------

    def stats(self) -> dict:
        def count(table):
            return self._query(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"]

        return {
            "accounts": count("accounts"),
            "channels": count("channels"),
            "server_bans": count("server_bans"),
            "fingerprints": count("account_fingerprints"),
            "schema_version": SCHEMA_VERSION,
            "path": self.path,
        }

    def __repr__(self):
        return f"<Storage {self.path} {json.dumps(self.stats(), default=str)}>"
