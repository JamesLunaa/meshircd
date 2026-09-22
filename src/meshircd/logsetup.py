"""Logging configuration.

Two formats. ``text`` is for a terminal and for journald, which already
adds its own timestamps and structure. ``json`` is for anything that ships
logs to an aggregator, where one object per line is far easier to query
than a regex over a human sentence.

The rule that matters more than the format: credentials must never reach a
log. ``redact`` is applied to every raw protocol line before it is logged,
because AUTHENTICATE carries the SASL password as base64 -- which is
encoding, not encryption.
"""

from __future__ import annotations

import json
import logging
import sys
import time

REDACTED = "[redacted]"

# Commands whose parameters are, or may contain, a credential.
_SENSITIVE_COMMANDS = {"AUTHENTICATE", "PASS", "OPER", "NS", "NICKSERV"}


def redact(line: str) -> str:
    """Strip credentials from a raw protocol line before logging it."""
    if not line:
        return line
    stripped = line.lstrip()
    if stripped.startswith("@"):
        _, _, stripped = stripped.partition(" ")
    if stripped.startswith(":"):
        _, _, stripped = stripped.partition(" ")
    command, sep, rest = stripped.partition(" ")
    upper = command.upper()
    if upper not in _SENSITIVE_COMMANDS or not sep:
        return line
    if upper == "OPER":
        # OPER <name> <password>: the name is useful, the password is not.
        name, _, _ = rest.partition(" ")
        return f"OPER {name} {REDACTED}"
    return f"{upper} {REDACTED}"


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in getattr(record, "fields", {}).items():
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure(level: str = "INFO", fmt: str = "text") -> logging.Logger:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s  %(message)s",
                              datefmt="%Y-%m-%dT%H:%M:%S")
        )
    root.addHandler(handler)
    try:
        root.setLevel(getattr(logging, level.upper()))
    except AttributeError:
        root.setLevel(logging.INFO)
    return logging.getLogger("ircd")
