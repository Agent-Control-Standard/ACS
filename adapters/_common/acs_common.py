"""
Shared ACS v0.1.0 helpers used by the three reference adapters and the
example Guardian.

Lives in `adapters/_common/`. Each adapter prepends this directory to
`sys.path` and imports the symbols it needs.

What's in here:

- `jcs_canonicalize` — RFC 8785 (JCS) canonicalization. Uses the
  `rfc8785` PyPI package when available (full compliance including
  number edge cases); falls back to a sorted-keys + compact-separators
  implementation otherwise, which is JCS-equivalent for all JSON
  shapes ACS envelopes carry.
- `derive_session_key` — HKDF-SHA256 per-session key derivation per §10.
- `sign_envelope` / `verify_signature` — HMAC-SHA256 baseline signature
  over JCS(envelope with signature field removed), per §10.
- `load_hmac_secret` — read the HMAC secret from `ACS_HMAC_SECRET_FILE`
  (preferred: file mode 0600) or `ACS_HMAC_SECRET` (env). File path
  beats env var so secrets don't sit in `ps aux` output.
- `iso8601_now` / `coerce_uuid` / `parse_iso8601` — time + ID helpers.
- `audit_event` — structured `ACS_AUDIT` line for §6.4 fail-open bypass.
- `do_handshake` / `ping` — protocol helpers (§4, §13).
- `session_state` — per-session JSON file used by adapters to track
  last_step_id, seen_step_ids, etc. across separate hook-process
  invocations (shell-stdin adapters spawn one process per hook).
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

try:
    import rfc8785 as _rfc8785  # type: ignore[import-not-found]
    _HAVE_RFC8785 = True
except ImportError:
    _rfc8785 = None
    _HAVE_RFC8785 = False


def jcs_canonicalize(obj: Any) -> bytes:
    """RFC 8785 (JSON Canonicalization Scheme).

    Uses the `rfc8785` package when installed (full RFC 8785 compliance,
    including float / -0 / subnormal handling and Unicode normalization).
    Falls back to a sorted-keys + compact-separators implementation
    when not, which is JCS-equivalent for all JSON shapes ACS envelopes
    carry but does not handle every floating-point edge case.

    Install rfc8785 for full compliance: pip install rfc8785
    """
    if _HAVE_RFC8785:
        return _rfc8785.dumps(obj)
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


def load_hmac_secret() -> bytes:
    """Read the HMAC input keying material.

    Resolution order (first hit wins):
    1. `ACS_HMAC_SECRET_FILE` — path to a file containing the secret.
       Preferred for production. Use `chmod 600` and own the file with
       the same user the adapter/Guardian runs as. The file's full byte
       content (stripped of trailing whitespace) is the secret.
    2. `ACS_HMAC_SECRET` — env-var fallback. Quick for dev, less secure
       (visible in `ps eauxw`, child-process envs, core dumps).
    3. Empty bytes — caller decides whether that means dev-mode or fail.

    Generate a secret: `openssl rand -hex 32 > /etc/acs/hmac.key`
    """
    path = os.environ.get("ACS_HMAC_SECRET_FILE", "").strip()
    if path:
        try:
            with open(path, "rb") as f:
                return f.read().rstrip(b"\r\n\t ")
        except OSError:
            return b""
    env_val = os.environ.get("ACS_HMAC_SECRET", "")
    return env_val.encode("utf-8") if env_val else b""


# Back-compat alias for internal callers.
_signing_secret = load_hmac_secret


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


# ----- Per-session adapter state (cross-invocation) -----
#
# Shell-stdin adapters (claude-code, cursor) spawn one process per hook
# event. To accumulate state across events in the same session (last
# step_id, step_ids seen, subagent registry, etc.) the adapter persists
# a small JSON file in the cache directory.

_SESSION_STATE_DIR = Path(
    os.environ.get(
        "ACS_SESSION_STATE_DIR",
        os.path.join(os.path.expanduser("~"), ".cache", "acs-adapter-session"),
    )
)


def _session_state_path(session_id: str) -> Path:
    key = hashlib.sha256(session_id.encode()).hexdigest()[:16]
    return _SESSION_STATE_DIR / f"{key}.json"


def load_session_state(session_id: str) -> dict:
    """Return the session-state dict for `session_id`, or an empty dict."""
    if not session_id:
        return {}
    path = _session_state_path(session_id)
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_session_state(session_id: str, state: dict) -> None:
    """Persist the session-state dict atomically. No-op on session_id empty."""
    if not session_id:
        return
    try:
        _SESSION_STATE_DIR.mkdir(parents=True, exist_ok=True)
        path = _session_state_path(session_id)
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, path)
    except OSError:
        pass


def record_step(session_id: str, step_id: str) -> None:
    """Append step_id to the session's seen-list and update last_step_id."""
    if not session_id or not step_id:
        return
    st = load_session_state(session_id)
    seen = st.setdefault("seen_step_ids", [])
    if step_id not in seen:
        seen.append(step_id)
        # Bound the list so it doesn't grow unbounded across long sessions
        if len(seen) > 1000:
            del seen[: len(seen) - 1000]
    st["last_step_id"] = step_id
    save_session_state(session_id, st)


# ----- Sys-path bootstrap for adapters in sibling directories -----

def install_path_for_sibling() -> None:
    """Convenience: ensures the _common dir is on sys.path so adapters in
    sibling directories can `from acs_common import ...`. No-op if
    already on path."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
