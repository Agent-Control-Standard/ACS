"""
Shared ACS v0.1.0 helpers used by the three reference adapters and the
example Guardian.

Lives in `adapters/_common/`. Each adapter prepends this directory to
`sys.path` and imports the symbols it needs.

What's in here:

- `jcs_canonicalize` — minimal RFC 8785 (JCS) canonicalization sufficient
  for the JSON shapes ACS envelopes carry. Production deployments
  needing full JCS (very small floats, Unicode normalization edges)
  should drop in the `rfc8785` package; the entry-point signature is
  the same.
- `derive_session_key` — HKDF-SHA256 per-session key derivation from
  shared input keying material (`ACS_HMAC_SECRET`) and `session_id`,
  per Specification §10.
- `sign_envelope` / `verify_signature` — HMAC-SHA256 baseline signature
  over the canonical input defined in §10: the JCS canonicalization of
  the envelope with the `signature` field removed.
- `iso8601_now` — RFC3339 UTC timestamp with millisecond precision.
- `coerce_uuid` — stable UUID coercion (UUID passthrough; uuid5 for
  non-UUID inputs).
- `audit_event` — structured audit-event line emitter for fail-open
  bypass recording (§6.4).
- `do_handshake` — perform `handshake/hello` and cache result per
  session in a process-local file (`~/.cache/acs-adapter-handshake/`).
- `ping` — `system/ping` helper for adapters that want a liveness probe.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

ACS_VERSION = "0.1.0"
DEFAULT_SKEW_WINDOW_MS = 300_000


# ----- Canonicalization -----

def jcs_canonicalize(obj: Any) -> bytes:
    """RFC 8785 (JSON Canonicalization Scheme) — sufficient for ACS envelopes.

    The full RFC covers number serialization edge cases (-0, subnormals,
    very large integers) that ACS envelopes do not contain. For our
    integer durations and string-only payload fields, json.dumps with
    sort_keys and compact separators produces JCS-equivalent output.
    Drop in the `rfc8785` package if your deployment carries arbitrary
    JSON.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ----- Signing (HMAC-SHA256 baseline per §10) -----

def derive_session_key(input_key_material: bytes, session_id: str) -> bytes:
    """HKDF-SHA256 with session_id as `info`, no salt.

    Spec §10: 'per-session HMAC key is HKDF-derived from deployment-provided
    input keying material (a pre-shared secret, or a transport channel
    binding such as a TLS exporter) together with the session_id.'
    """
    # HKDF-Extract with empty salt
    prk = hmac.new(b"\x00" * 32, input_key_material, hashlib.sha256).digest()
    # HKDF-Expand to 32 bytes with info = session_id
    info = session_id.encode("utf-8")
    t = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t  # one 32-byte block is enough for HMAC-SHA256


def _signing_secret() -> bytes:
    """Read ACS_HMAC_SECRET from env. Returns an empty bytes if unset
    (caller decides what to do — typically skip signing for local dev)."""
    s = os.environ.get("ACS_HMAC_SECRET", "")
    return s.encode("utf-8") if s else b""


def sign_envelope(envelope: dict, *, key: bytes | None = None,
                  session_id: str | None = None, key_id: str = "default") -> dict:
    """Add a signature to the envelope. Returns the envelope unchanged
    if no key material is available (caller's responsibility to log)."""
    if key is None:
        ikm = _signing_secret()
        if not ikm:
            return envelope
        if not session_id:
            params = envelope.get("params") or envelope.get("result") or {}
            meta = params.get("metadata") or {}
            session_id = meta.get("session_id") or params.get("request_id") or ""
        key = derive_session_key(ikm, session_id)

    # Find where to put the signature: params for requests, result for responses
    container_key = "params" if "method" in envelope else "result"
    container = envelope.get(container_key, {})
    # Strip any existing signature before signing
    unsigned_container = {k: v for k, v in container.items() if k != "signature"}
    unsigned_envelope = {**envelope, container_key: unsigned_container}

    sig_bytes = hmac.new(key, jcs_canonicalize(unsigned_envelope), hashlib.sha256).digest()
    import base64
    container["signature"] = {
        "algorithm": "HMAC-SHA256",
        "value": base64.b64encode(sig_bytes).decode("ascii"),
        "key_id": key_id,
    }
    envelope[container_key] = container
    return envelope


def verify_signature(envelope: dict, *, key: bytes | None = None,
                     session_id: str | None = None) -> bool:
    """Verify a signed envelope. Returns True if valid (or if no signature
    present and no key material configured — local-dev mode)."""
    container_key = "params" if "method" in envelope else "result"
    container = envelope.get(container_key) or {}
    sig = container.get("signature")
    if sig is None:
        # No signature on the wire; valid only if local-dev (no key configured)
        return not bool(_signing_secret())

    if sig.get("algorithm") != "HMAC-SHA256":
        return False
    expected_b64 = sig.get("value")
    if not expected_b64:
        return False

    if key is None:
        ikm = _signing_secret()
        if not ikm:
            # Signature present but no key configured: cannot verify
            return False
        meta = container.get("metadata") or {}
        session_id = session_id or meta.get("session_id") or container.get("request_id") or ""
        key = derive_session_key(ikm, session_id)

    unsigned_container = {k: v for k, v in container.items() if k != "signature"}
    unsigned_envelope = {**envelope, container_key: unsigned_container}
    expected_bytes = hmac.new(key, jcs_canonicalize(unsigned_envelope), hashlib.sha256).digest()
    import base64
    return hmac.compare_digest(expected_bytes, base64.b64decode(expected_b64))


# ----- Time + IDs -----

def iso8601_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def coerce_uuid(raw: str | None, *, namespace_prefix: str = "acs") -> str:
    if not raw:
        return str(uuid.uuid4())
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{namespace_prefix}:{raw}"))


def parse_iso8601(ts: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ----- Audit events (§6.4 fail-open recording) -----

def audit_event(event_type: str, **fields: Any) -> None:
    """Emit a structured audit-event line to stderr.

    §6.4: 'Every step that proceeds without a decision MUST be recorded
    as an audit event, so the bypass is visible rather than silent.'

    Deployments redirect or parse the `ACS_AUDIT` prefix to feed a real
    audit sink. The line is single-line JSON for trivial line-oriented
    ingestion.
    """
    payload = {
        "acs_audit_event": event_type,
        "timestamp": iso8601_now(),
        **fields,
    }
    sys.stderr.write("ACS_AUDIT " + json.dumps(payload, sort_keys=True) + "\n")
    sys.stderr.flush()


# ----- Handshake (§4) -----

_HANDSHAKE_CACHE_DIR = Path(
    os.environ.get(
        "ACS_HANDSHAKE_CACHE",
        os.path.join(os.path.expanduser("~"), ".cache", "acs-adapter-handshake"),
    )
)


def _handshake_cache_path(session_id: str, guardian_url: str) -> Path:
    key = hashlib.sha256((session_id + "|" + guardian_url).encode()).hexdigest()[:16]
    return _HANDSHAKE_CACHE_DIR / f"{key}.json"


def do_handshake(
    *,
    guardian_url: str,
    session_id: str,
    agent_id: str,
    platform: str,
    methods_implemented: list[str],
    wrapped_protocols: list[str] | None = None,
    timeout: float = 5.0,
) -> dict | None:
    """Perform handshake/hello with the Guardian; return ServerHello or None.

    Caches the ServerHello in a small JSON file keyed by (session_id,
    guardian_url). Repeat calls within the same session reuse the cache;
    a process spawned fresh for each shell-hook event will hit the cache
    after the first call.
    """
    cache = _handshake_cache_path(session_id, guardian_url)
    if cache.exists():
        try:
            with open(cache) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    client_hello = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "handshake/hello",
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": iso8601_now(),
            "metadata": {"agent_id": agent_id, "session_id": session_id, "platform": platform},
            "payload": {
                "acs_versions_supported": [ACS_VERSION],
                "methods_implemented": methods_implemented,
                "transports_supported": ["http", "stdio"],
                "max_payload_size_bytes": 1_000_000,
                "provenance_producer": "none",
                "wrapped_protocols": wrapped_protocols or [],
                "profiles_supported": ["acs-core"],
                "signature_algorithms_supported": (
                    ["HMAC-SHA256"] if _signing_secret() else []
                ),
            },
        },
    }
    sign_envelope(client_hello, session_id=session_id)
    try:
        body = json.dumps(client_hello).encode("utf-8")
        req = urllib.request.Request(
            guardian_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            response = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None

    result = response.get("result") or {}
    server_hello = result.get("payload")
    if server_hello:
        try:
            _HANDSHAKE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
            with open(cache, "w") as f:
                json.dump(server_hello, f)
        except OSError:
            pass
    return server_hello


# ----- system/ping (§13) -----

def ping(guardian_url: str, *, echo: str = "ping", timeout: float = 2.0) -> dict | None:
    """Send a system/ping and return the result, or None on failure.

    Per §13: Guardian MUST always return allow; ping does not participate
    in the chain; no signature required.
    """
    request = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "system/ping",
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": iso8601_now(),
            "metadata": {"agent_id": "ping-client", "session_id": str(uuid.uuid4())},
            "payload": {"echo": echo},
        },
    }
    try:
        body = json.dumps(request).encode("utf-8")
        req = urllib.request.Request(
            guardian_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")).get("result")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


# ----- Sys-path bootstrap for adapters in sibling directories -----

def install_path_for_sibling() -> None:
    """Convenience: ensures the _common dir is on sys.path so adapters in
    sibling directories can `from acs_common import ...`. No-op if
    already on path."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
