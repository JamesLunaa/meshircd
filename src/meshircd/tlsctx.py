"""TLS context construction and certificate reloading.

The encryption boundary this server sits on:

    IRC client
        |  plaintext IRC protocol
        v
    TLS layer            <-- this module configures it
        |  encrypted bytes
        v
    TCP connection
        |
    IRC server

TLS changes nothing about the IRC protocol itself; it changes whether the
bytes carrying that protocol are readable on the wire. It also does not
hide *that* a connection happened -- a capture still shows the handshake
and the certificate. It hides what was said.

Certificates expire, and on a server using ACME they are replaced every
few weeks. ``reload`` rebuilds the context in place so a renewal is a
SIGHUP rather than a restart that disconnects everyone.
"""

from __future__ import annotations

import hashlib
import os
import ssl


class TLSError(Exception):
    pass


def build_context(cfg) -> ssl.SSLContext:
    """Build a server-side SSLContext from the [tls] config section."""
    if not cfg.cert or not cfg.key:
        raise TLSError("TLS requested but [tls] cert/key are not configured")
    for path, label in ((cfg.cert, "cert"), (cfg.key, "key")):
        if not os.path.exists(path):
            raise TLSError(f"tls.{label}: file not found: {path}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cfg.cert, cfg.key)
    except (ssl.SSLError, OSError) as exc:
        raise TLSError(f"could not load certificate/key: {exc}") from None

    try:
        context.minimum_version = getattr(ssl.TLSVersion, cfg.min_version)
    except AttributeError:
        raise TLSError(f"unknown tls.min_version: {cfg.min_version}") from None

    # Pin these explicitly rather than inheriting whatever a future stdlib
    # or OpenSSL default happens to be.
    context.options |= ssl.OP_NO_COMPRESSION  # mitigates CRIME
    context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
    if cfg.prefer_server_ciphers:
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    try:
        context.set_ciphers(cfg.ciphers)
    except ssl.SSLError as exc:
        raise TLSError(f"tls.ciphers rejected by OpenSSL: {exc}") from None

    if cfg.request_client_cert:
        # CERT_OPTIONAL lets a client connect without a certificate, but
        # any certificate it *does* present must verify -- the stdlib gives
        # us no way to accept an unverifiable one. Requiring a CA here is
        # therefore not optional: without it, OpenSSL rejects every
        # self-signed client certificate and those users cannot connect.
        if not cfg.client_ca:
            raise TLSError(
                "tls.request_client_cert is on but tls.client_ca is not set. "
                "Python's ssl module cannot accept an unverifiable client "
                "certificate, so without a CA bundle any client presenting "
                "a certificate would be unable to connect at all."
            )
        if not os.path.exists(cfg.client_ca):
            raise TLSError(f"tls.client_ca: file not found: {cfg.client_ca}")
        try:
            context.load_verify_locations(cfg.client_ca)
        except (ssl.SSLError, OSError) as exc:
            raise TLSError(f"tls.client_ca could not be loaded: {exc}") from None
        context.verify_mode = ssl.CERT_OPTIONAL
        context.check_hostname = False

    return context


def peer_fingerprint(ssl_object) -> str | None:
    """SHA-256 fingerprint of the client certificate, if one was offered."""
    if ssl_object is None:
        return None
    try:
        der = ssl_object.getpeercert(binary_form=True)
    except (ValueError, AttributeError):
        return None
    if not der:
        return None
    return hashlib.sha256(der).hexdigest()


class ReloadableTLS:
    """Holds the current context and swaps it on reload.

    asyncio captures the context object when the listener starts, so the
    same object has to be mutated rather than replaced. ``load_cert_chain``
    on a live context affects only handshakes started afterwards, which is
    exactly the semantics a certificate renewal wants.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.context = build_context(cfg)
        self.fingerprint = self._cert_fingerprint()

    def _cert_fingerprint(self) -> str | None:
        try:
            with open(self.cfg.cert, "rb") as handle:
                return hashlib.sha256(handle.read()).hexdigest()[:16]
        except OSError:
            return None

    def reload(self, cfg=None) -> bool:
        """Re-read the certificate. Returns True if it actually changed.

        A failed reload leaves the previous certificate in place: a broken
        or half-written cert file during renewal must not take the server
        down.
        """
        self.cfg = cfg or self.cfg
        digest = self._cert_fingerprint()
        if digest is not None and digest == self.fingerprint:
            return False
        self.context.load_cert_chain(self.cfg.cert, self.cfg.key)
        self.fingerprint = digest
        return True
