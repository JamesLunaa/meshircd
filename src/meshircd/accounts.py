"""Accounts: password hashing and the authentication decision.

Deliberately knows nothing about sockets, nicknames or channels.
Authenticating to an account and owning a nickname are separate concerns
here -- logging in as `alice` does not reserve the nick `alice` -- and
keeping this module ignorant of the IRC layer is what enforces that.

Passwords are stored only as salted scrypt hashes. Two properties are
load-bearing and easy to lose in a refactor:

- ``verify`` always performs a hash, even when the account does not exist.
  Returning early for an unknown name makes "no such account" measurably
  faster than "wrong password", which lets an attacker enumerate valid
  account names by timing alone.
- The comparison is ``hmac.compare_digest``, not ``==``, so the comparison
  itself does not leak how many leading bytes were correct.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from .protocol import casefold
from .storage import Storage

# scrypt cost parameters. n=2**14 is the interactive-login figure from
# RFC 7914: expensive enough to make offline cracking of a stolen database
# painful, cheap enough (~30ms) that a login does not feel slow. The cost
# is why hashing must never run on the event loop.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 64

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 512  # scrypt on unbounded input is a DoS vector.
MAX_ACCOUNT_NAME_LENGTH = 32


class AccountError(Exception):
    """A requested account operation is not valid."""


def hash_password(password: str, salt: bytes) -> bytes:
    if len(password) > MAX_PASSWORD_LENGTH:
        raise AccountError(f"password longer than {MAX_PASSWORD_LENGTH} characters")
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=DKLEN
    )


def new_hash(password: str) -> tuple[str, str]:
    """Return (salt_hex, hash_hex) for a fresh password."""
    salt = secrets.token_bytes(16)
    return salt.hex(), hash_password(password, salt).hex()


def validate_account_name(name: str) -> str:
    if not name or len(name) > MAX_ACCOUNT_NAME_LENGTH:
        raise AccountError(f"account name must be 1-{MAX_ACCOUNT_NAME_LENGTH} characters")
    if not all(c.isalnum() or c in "_-[]\\`^{|}" for c in name):
        raise AccountError("account name contains characters that are not allowed")
    return name


def validate_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AccountError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise AccountError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    return password


# A fixed salt used only to burn the same CPU time when an account does not
# exist. Generated per process so it is never a useful precomputation target.
_DUMMY_SALT = secrets.token_bytes(16)
_DUMMY_PASSWORD = secrets.token_hex(16)


class AccountStore:
    def __init__(self, storage: Storage):
        self.storage = storage

    # --- management (synchronous; used by the CLI and at startup) ------

    def create(self, name: str, password: str):
        validate_account_name(name)
        validate_password(password)
        key = casefold(name)
        if self.storage.get_account(key) is not None:
            raise AccountError(f"account {name!r} already exists")
        salt, digest = new_hash(password)
        self.storage.create_account(name, key, salt, digest)

    def delete(self, name: str):
        if not self.storage.delete_account(casefold(name)):
            raise AccountError(f"no such account {name!r}")

    def set_password(self, name: str, password: str):
        validate_password(password)
        salt, digest = new_hash(password)
        if not self.storage.set_account_password(casefold(name), salt, digest):
            raise AccountError(f"no such account {name!r}")

    def set_locked(self, name: str, locked: bool):
        if not self.storage.set_account_locked(casefold(name), locked):
            raise AccountError(f"no such account {name!r}")

    def exists(self, name: str) -> bool:
        return self.storage.get_account(casefold(name)) is not None

    def list(self) -> list[dict]:
        return [dict(row) for row in self.storage.list_accounts()]

    def add_fingerprint(self, name: str, fingerprint: str):
        key = casefold(name)
        if self.storage.get_account(key) is None:
            raise AccountError(f"no such account {name!r}")
        cleaned = fingerprint.replace(":", "").strip().lower()
        if len(cleaned) != 64 or not all(c in "0123456789abcdef" for c in cleaned):
            raise AccountError("fingerprint must be a 64-character SHA-256 hex digest")
        self.storage.add_fingerprint(cleaned, key)

    def remove_fingerprint(self, fingerprint: str):
        if not self.storage.remove_fingerprint(fingerprint.replace(":", "").strip().lower()):
            raise AccountError("no such fingerprint")

    def fingerprints(self, name: str) -> list[str]:
        return self.storage.list_fingerprints(casefold(name))

    # --- authentication (blocking; always call via to_thread) ----------

    def verify(self, name: str, password: str) -> str | None:
        """Return the account's display name on success, None on failure.

        Runs in a worker thread. The constant-work path for missing and
        locked accounts is intentional -- see the module docstring.
        """
        row = self.storage.get_account(casefold(name))
        if row is None or row["locked"]:
            hash_password(_DUMMY_PASSWORD, _DUMMY_SALT)
            return None
        try:
            candidate = hash_password(password, bytes.fromhex(row["salt"]))
        except AccountError:
            return None
        if not hmac.compare_digest(candidate, bytes.fromhex(row["hash"])):
            return None
        self.storage.touch_account_login(row["name_lower"])
        return row["name"]

    def verify_fingerprint(self, fingerprint: str) -> str | None:
        """CertFP: authenticate by TLS client-certificate fingerprint.

        No password is involved, so there is no hash to time-equalise --
        the fingerprint is a 256-bit secret the client proved possession of
        during the TLS handshake.
        """
        if not fingerprint:
            return None
        row = self.storage.account_for_fingerprint(fingerprint)
        if row is None or row["locked"]:
            return None
        self.storage.touch_account_login(row["name_lower"])
        return row["name"]


def verify_config_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """Check a password against a hash stored in the config file (oper
    blocks and the server PASS). Same constant-time discipline."""
    if not salt_hex or not hash_hex:
        return False
    try:
        candidate = hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(candidate, bytes.fromhex(hash_hex))
    except (ValueError, AccountError):
        return False
