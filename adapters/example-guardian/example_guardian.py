#!/usr/bin/env python3
"""
Minimal local Guardian for testing the reference adapters.

Implements the ACS v0.1.0 spec features the adapters exercise:

- Wire envelope per `request-envelope.json` / `response-envelope.json`.
- HMAC-SHA256 baseline signing (§10) with HKDF-derived per-session key.
- Rolling SHA-256 audit chain per §8.2 (`entry_hash = sha256(JCS(entry) || previous_hash)`).
- Replay rejection on duplicate `request_id` (§10.3, error -32005).
- Timestamp skew rejection (§10.3, error -32006).
- `handshake/hello` with ClientHello/ServerHello (§4).
- `system/ping` always returns allow, never enters the chain (§13).
- Subagent gating: blocks `Task` tool by default.
- Destructive-Bash regex + protected-system-path Write blocks.

This is NOT a production Guardian. It is a teaching artifact and a test
substrate for the reference adapters.

Wire format ground truth:
  `specification/v0.1.0/request-envelope.json`
  `specification/v0.1.0/response-envelope.json`
  `specification/v0.1.0/handshake.json`
  `specification/v0.1.0/hooks/*.json`

Usage:
  python3 example_guardian.py [--port 8787]

Environment variables:
  ACS_HMAC_SECRET / ACS_HMAC_SECRET_FILE
                      Shared secret for HMAC-SHA256 signing per §10. The
                      Guardian verifies every signed request and signs
                      every response. **The Guardian refuses to start
                      unless one of these is set, or `ACS_DEV_MODE=1`.**
                      File path is preferred for production (no exposure
                      in `ps aux`); use `chmod 600`.
                      Generate: `openssl rand -hex 32 > /etc/acs/hmac.key`
  ACS_DEV_MODE        "1" allows starting without a signing secret. Local
                      development only. ACS-Core baseline integrity (§10)
                      is not satisfied in dev mode.
  ACS_SKEW_WINDOW_MS  Timestamp skew tolerance (default 300_000 = 5 min).
  ACS_ALLOW_SUBAGENT  "1" allows the Task tool. Default "0" gates it.
  ACS_GUARDIAN_STATE_DIR
                      Directory where per-session state (chain head +
                      seen request_ids) is persisted. Survives Guardian
                      restart so §10.3 replay protection isn't reset by
                      crashes / deploys / autoscaling. Defaults to
                      ~/.cache/acs-guardian-state/. Set to "" to disable
                      persistence (RAM-only; dev/test only — opens a
                      replay window across restarts).
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import http.server
import json
import os
import re
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
from acs_common import (  # noqa: E402
    ACS_VERSION,
    DEFAULT_SKEW_WINDOW_MS,
    DESTRUCTIVE_SCAN_MAX_LEN,
    MAX_REQUEST_BODY_BYTES,
    derive_session_key,
    iso8601_now,
    jcs_canonicalize,
    load_hmac_secret,
    parse_iso8601,
    sign_envelope,
    verify_signature,
)

import datetime

# Optional spec-schema validation. If jsonschema + a local clone of the
# canonical schemas (ACS_SPEC_DIR) are present, the Guardian validates
# every incoming envelope against request-envelope.json BEFORE policy
# evaluation — so malformed payloads from a buggy adapter or hostile
# input are rejected with INVALID_REQUEST instead of slipping into
# downstream code.
_SPEC_VALIDATION_AVAILABLE = False
_REQUEST_ENVELOPE_VALIDATOR = None
try:
    from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    from jsonschema.validators import RefResolver  # type: ignore[import-not-found]
    _spec_dir_env = os.environ.get(
        "ACS_SPEC_DIR",
        "/tmp/acs-spec-source/specification/v0.1.0",
    )
    _spec_dir = Path(_spec_dir_env)
    _envelope_schema_path = _spec_dir / "request-envelope.json"
    if _envelope_schema_path.exists():
        with open(_envelope_schema_path) as _f:
            _schema_obj = json.load(_f)
        _REQUEST_ENVELOPE_VALIDATOR = Draft202012Validator(
            _schema_obj,
            resolver=RefResolver(
                base_uri=(_spec_dir.as_uri() + "/request-envelope.json"),
                referrer=_schema_obj,
            ),
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )
        _SPEC_VALIDATION_AVAILABLE = True
except ImportError:
    pass


SKEW_WINDOW_MS = int(os.environ.get("ACS_SKEW_WINDOW_MS", str(DEFAULT_SKEW_WINDOW_MS)))
ALLOW_SUBAGENT = os.environ.get("ACS_ALLOW_SUBAGENT", "0") == "1"


def _hmac_secret() -> bytes:
    """Re-read on every call so operators can rotate the secret without
    restarting the Guardian (rotate the file under `ACS_HMAC_SECRET_FILE`
    or update `ACS_HMAC_SECRET` and the next signature check picks it up).
    The handshake's advertised `signature_algorithms_supported` reflects
    the current value each time a ClientHello arrives."""
    return load_hmac_secret()


# ----- Destructive-Bash regex set -----

DESTRUCTIVE_BASH_PATTERNS: tuple[re.Pattern, ...] = (
    # Pattern 0: `rm` + a flag token that contains both r and f in any
    # order, possibly with other letters anywhere (-rf, -fr, -rfv,
    # -rfvi, -vrf, etc.), followed eventually by a path starting with
    # `/`, `~`, or `$HOME`. The trailing `[a-zA-Z]*` after the second
    # required flag letter is the bug-fix — without it, `-rfv` only
    # matched `-rf` and then `\b` failed against `v`, letting `rm -rfv`
    # slip through the policy. (CVE-class evasion: trivial single-letter
    # extension defeats the regex.)
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|--recursive\s+--force|--force\s+--recursive)\b.*?\s+(/|~|\$HOME)", re.IGNORECASE),
    re.compile(r"\brm\s+(-rf|-fr|--recursive\s+--force|--force\s+--recursive)\s+(/|~|\$HOME)(\s|$)", re.IGNORECASE),
    re.compile(r"\brm\s+.*--no-preserve-root\b", re.IGNORECASE),
    re.compile(r"\bmkfs(\.\w+)?\s+", re.IGNORECASE),
    re.compile(r"\bdd\s+.*\bof=/dev/", re.IGNORECASE),
    re.compile(r":\(\)\s*\{"),
    re.compile(r">\s*/dev/(sd[a-z]|nvme|hd[a-z]|disk)", re.IGNORECASE),
    re.compile(r"\bfind\s+(/|~|\$HOME)\b.*-delete\b", re.IGNORECASE),
    re.compile(r"\bfind\s+(/|~|\$HOME)\b.*-exec\s+rm\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+(-R\s+)?[0-7]*7{2,}[0-7]*\s+(/etc|/usr|/bin|/sbin)", re.IGNORECASE),
)

PROTECTED_PATH_PREFIXES: tuple[str, ...] = ("/etc/", "/usr/", "/bin/", "/sbin/", "/boot/")

INFORMATIONAL_METHODS = {
    "steps/sessionStart", "steps/sessionEnd", "steps/userMessage",
    "steps/toolCallResult", "steps/agentResponse",
    "steps/preCompact", "steps/postCompact",
    "steps/subagentStart", "steps/subagentStop",
    "steps/knowledgeRetrieval", "steps/memoryStore", "steps/memoryContextRetrieval",
    "steps/turnStart", "steps/turnEnd", "steps/agentTrigger",
}


# ----- Per-session state (replay + chain), persisted across restarts -----
#
# RAM-only state was a real production gap: a Guardian restart wiped the
# seen-request-id set, opening a replay window for every previously-sent
# envelope. §10.3 says Guardians MUST reject duplicates; that MUST
# doesn't pause for the duration of a deploy. Per-session state now
# persists to a small JSON file per session_id under ACS_GUARDIAN_STATE_DIR
# so the seen set + chain head survive process restarts.

_STATE_DIR_ENV = os.environ.get(
    "ACS_GUARDIAN_STATE_DIR",
    os.path.join(os.path.expanduser("~"), ".cache", "acs-guardian-state"),
)
PERSIST_ENABLED = bool(_STATE_DIR_ENV)
STATE_DIR = Path(_STATE_DIR_ENV) if PERSIST_ENABLED else None


def _state_path(session_id: str) -> Path | None:
    if not PERSIST_ENABLED:
        return None
    key = hashlib.sha256(session_id.encode()).hexdigest()[:16]
    return STATE_DIR / f"{key}.json"


class SessionState:
    """Holds the rolling chain head and replay protection per session_id.

    Persists to disk after every mutation so Guardian restart cannot
    open a replay window. JSON file per session_id, mode 0600, in
    STATE_DIR. Loading is best-effort: a corrupt file behaves like a
    fresh session.

    seen_request_ids is a dict {request_id: timestamp_seconds} so old
    entries can be evicted by `evict_old_request_ids` — without
    eviction, long-running sessions accumulate UUIDs without bound.
    """

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id
        self.previous_hash: str | None = None  # None for the first entry (§8.1)
        self.seen_request_ids: dict[str, float] = {}
        self.seen_nonces: dict[str, float] = {}
        self.lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        path = _state_path(self.session_id)
        if path is None or not path.exists():
            return
        try:
            # Backwards-compat: older state files stored seen_request_ids as a
            # list. Treat any list entry as having timestamp 0 (will be evicted
            # immediately if past the cutoff).
            # Hold a shared (read) flock so we don't read a partially-written
            # file from a concurrent persist() in another Guardian instance.
            with open(path) as f:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                except OSError:
                    pass
                try:
                    data = json.load(f)
                finally:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass
            self.previous_hash = data.get("previous_hash")
            sr = data.get("seen_request_ids", {})
            self.seen_request_ids = sr if isinstance(sr, dict) else {x: 0.0 for x in sr}
            sn = data.get("seen_nonces", {})
            self.seen_nonces = sn if isinstance(sn, dict) else {x: 0.0 for x in sn}
        except (OSError, json.JSONDecodeError):
            pass

    def persist(self) -> None:
        """Atomically write the current state, with file-locked
        merge-on-write to support multiple Guardian instances sharing a
        STATE_DIR (HA deploys). Must be called with self.lock held.

        Algorithm:
          1. Take an exclusive flock on a sidecar `.lock` file.
          2. Re-read the on-disk state (another instance may have just
             written it).
          3. Merge the in-memory state into the on-disk state — union
             of seen_request_ids/nonces, max-by-length of previous_hash
             (chain forks across instances are a separate problem).
          4. Atomically write the merged result.
          5. Release the flock.
        """
        path = _state_path(self.session_id)
        if path is None:
            return
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(STATE_DIR, 0o700)
            except OSError:
                pass
            lock_path = path.with_suffix(".lock")
            lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                except OSError as e:
                    if e.errno != errno.ENOLCK:
                        raise

                # Re-read on-disk state for merge
                merged_seen = dict(self.seen_request_ids)
                merged_nonces = dict(self.seen_nonces)
                merged_prev = self.previous_hash
                if path.exists():
                    try:
                        with open(path) as rf:
                            disk = json.load(rf)
                        disk_seen = disk.get("seen_request_ids") or {}
                        # Backwards-compat: tolerate list form from earlier versions
                        if isinstance(disk_seen, list):
                            disk_seen = {x: 0.0 for x in disk_seen}
                        for k, v in disk_seen.items():
                            # Keep the EARLIEST timestamp (so eviction works correctly)
                            if k not in merged_seen or merged_seen[k] > v:
                                merged_seen[k] = v
                        disk_nonces = disk.get("seen_nonces") or {}
                        if isinstance(disk_nonces, list):
                            disk_nonces = {x: 0.0 for x in disk_nonces}
                        for k, v in disk_nonces.items():
                            if k not in merged_nonces or merged_nonces[k] > v:
                                merged_nonces[k] = v
                        # Chain head: keep whichever exists (in single-Guardian
                        # mode both are identical; in HA mode, this is best-effort).
                        if not merged_prev and disk.get("previous_hash"):
                            merged_prev = disk["previous_hash"]
                    except (OSError, json.JSONDecodeError):
                        pass

                self.seen_request_ids = merged_seen
                self.seen_nonces = merged_nonces
                self.previous_hash = merged_prev

                tmp = path.with_suffix(".json.tmp")
                fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    json.dump({
                        "previous_hash": self.previous_hash,
                        "seen_request_ids": self.seen_request_ids,
                        "seen_nonces": self.seen_nonces,
                    }, f)
                os.replace(tmp, path)
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(lock_fd)
        except OSError:
            pass


def evict_old_request_ids(st: "SessionState") -> int:
    """Drop request_id entries older than 2 × skew_window.

    Replay is impossible past the skew window — Guardian would reject
    the request with TIMESTAMP_OUT_OF_WINDOW (-32006) before reaching
    the replay check. We use 2 × skew as the cutoff for safety margin
    against clock drift across processes. Caller must hold st.lock.

    Returns the number of entries evicted.
    """
    cutoff = time.time() - 2 * (SKEW_WINDOW_MS / 1000.0)
    old = [k for k, ts in st.seen_request_ids.items() if ts < cutoff]
    for k in old:
        del st.seen_request_ids[k]
    return len(old)


class GuardianState:
    """Process-global state. Sessions keyed by metadata.session_id."""

    def __init__(self) -> None:
        self.sessions: dict[str, SessionState] = {}
        self.lock = threading.Lock()

    def get(self, session_id: str) -> SessionState:
        with self.lock:
            st = self.sessions.get(session_id)
            if st is None:
                st = SessionState(session_id=session_id)
                self.sessions[session_id] = st
            return st


STATE = GuardianState()


# ----- Helpers -----

def _matches_destructive_bash(cmd: str) -> str | re.Pattern | None:
    """Returns:
      None         — safe (no destructive pattern matched)
      re.Pattern   — a destructive pattern matched
      "too_large"  — input exceeds the regex-scan cap; caller MUST treat
                     as suspicious (we don't know if it's destructive).

    The cap (DESTRUCTIVE_SCAN_MAX_LEN = 8 KiB) defends against regex
    DoS via crafted huge commands. Real shell commands are tiny;
    multi-KB strings are tunneled data or an attack.
    """
    if len(cmd) > DESTRUCTIVE_SCAN_MAX_LEN:
        return "too_large"
    for pat in DESTRUCTIVE_BASH_PATTERNS:
        if pat.search(cmd):
            return pat
    return None


def _unwrap_arguments(wrapped: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (wrapped or {}).items():
        out[k] = v["value"] if isinstance(v, dict) and "value" in v else v
    return out


# ----- Chain computation (§8.2 normative) -----

def compute_entry_hash(entry: dict, previous_hash: str | None) -> str:
    """entry_hash = lowercase-hex(SHA-256(content_bytes || prev_hash_bytes))

    content_bytes = UTF-8(JCS(entry with entry_hash and previous_hash REMOVED))
    prev_hash_bytes = raw 32-byte decoding of previous_hash, or empty bytes for the first entry.
    """
    entry_for_hash = {k: v for k, v in entry.items() if k not in ("entry_hash", "previous_hash")}
    content_bytes = jcs_canonicalize(entry_for_hash)
    prev_bytes = bytes.fromhex(previous_hash) if previous_hash else b""
    return hashlib.sha256(content_bytes + prev_bytes).hexdigest()


def append_to_chain(session_id: str, method: str, request_id: str,
                    payload_canonical: str, client_timestamp: str) -> str:
    """Append a ContextEntry to the session's chain, return the new chain head.

    Uses the client's request timestamp (already skew-validated upstream)
    so an external observer that records the request and the published
    chain_hash can fully recompute the entry and verify the hash. If the
    Guardian stamped its own time, the entry would be irreproducible.
    """
    st = STATE.get(session_id)
    with st.lock:
        entry = {
            "entry_id": request_id,
            "step_id": request_id,
            "step_type": method,
            "request_hash": hashlib.sha256(payload_canonical.encode()).hexdigest(),
            "timestamp": client_timestamp or iso8601_now(),
        }
        if st.previous_hash is not None:
            entry["previous_hash"] = st.previous_hash
        new_head = compute_entry_hash(entry, st.previous_hash)
        st.previous_hash = new_head
        st.persist()  # so a restart picks up the chain head
        return new_head


# ----- Replay + skew checks (§10.3 normative) -----

class GuardianError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def check_replay(session_id: str, request_id: str) -> None:
    if not request_id:
        return
    st = STATE.get(session_id)
    with st.lock:
        # HA-mode: re-read on-disk state so we see what other Guardian
        # instances have already accepted for this session.
        st._load()
        if request_id in st.seen_request_ids:
            raise GuardianError(-32005, f"REPLAY_DETECTED: request_id {request_id} already seen in session")
        # Evict opportunistically — every 100 new request_ids
        if len(st.seen_request_ids) % 100 == 0:
            evict_old_request_ids(st)
        st.seen_request_ids[request_id] = time.time()
        st.persist()  # flock + merge — visible to other instances


def check_skew(timestamp: str) -> None:
    if not timestamp:
        return
    try:
        ts = parse_iso8601(timestamp)
    except (ValueError, AttributeError):
        raise GuardianError(-32006, f"TIMESTAMP_OUT_OF_WINDOW: cannot parse timestamp {timestamp!r}")
    now = datetime.datetime.now(datetime.timezone.utc)
    delta_ms = abs((now - ts).total_seconds() * 1000)
    if delta_ms > SKEW_WINDOW_MS:
        raise GuardianError(-32006, f"TIMESTAMP_OUT_OF_WINDOW: {int(delta_ms)}ms > {SKEW_WINDOW_MS}ms")


def check_signature(envelope: dict, session_id: str) -> None:
    if not _hmac_secret():
        return  # local-dev mode
    if not verify_signature(envelope, session_id=session_id):
        raise GuardianError(-32004, "SIGNATURE_INVALID")


# ----- Method evaluators -----

def evaluate_handshake(params: dict, request_id: str) -> dict:
    """§4: ClientHello in payload; return ServerHello in result.payload."""
    client_hello = params.get("payload") or {}
    client_versions = client_hello.get("acs_versions_supported") or []
    if ACS_VERSION not in client_versions:
        raise GuardianError(-32001, f"UNSUPPORTED_VERSION: client supports {client_versions}, Guardian speaks {ACS_VERSION}")

    server_hello = {
        "negotiated_version": ACS_VERSION,
        "methods_evaluated": client_hello.get("methods_implemented") or [],
        "selected_transport": "http",
        "signature_algorithms_supported": (["HMAC-SHA256"] if _hmac_secret() else []),
        "timeout_config": {"default_ms": 5000},
        "skew_window_ms": SKEW_WINDOW_MS,
        "on_decision_failure": "proceed",  # spec default per §6.4
        "policy_requires_provenance": False,
        "profiles_accepted": ["acs-core"],
    }
    return {
        "type": "final",
        "acs_version": ACS_VERSION,
        "request_id": request_id,
        "decision": "allow",
        "payload": server_hello,
    }


def evaluate_ping(params: dict, request_id: str) -> dict:
    """§13: always allow; result.payload carries {status, echo, server_timestamp}."""
    echo = (params.get("payload") or {}).get("echo", "")
    return {
        "type": "final",
        "acs_version": ACS_VERSION,
        "request_id": request_id,
        "decision": "allow",
        "payload": {
            "status": "ok",
            "echo": echo,
            "server_timestamp": iso8601_now(),
        },
    }


def evaluate_step(method: str, params: dict, request_id: str, chain_hash: str) -> dict:
    payload = params.get("payload") or {}

    base = {
        "type": "final",
        "acs_version": ACS_VERSION,
        "request_id": request_id,
        "chain_hash": chain_hash,
    }

    if method == "steps/toolCallRequest":
        tool = payload.get("tool") or {}
        tool_name = tool.get("name", "")
        args = _unwrap_arguments(payload.get("arguments") or {})

        if tool_name == "Task" and not ALLOW_SUBAGENT:
            return {**base, "decision": "deny",
                    "reasoning": "Task tool (in-process subagent) is gated by default. Set ACS_ALLOW_SUBAGENT=1 to allow.",
                    "reason_codes": ["subagent_gated"]}

        if tool_name in ("Bash", "Shell"):
            cmd = args.get("command", "") or ""
            match = _matches_destructive_bash(cmd)
            if match == "too_large":
                return {**base, "decision": "deny",
                        "reasoning": f"command length {len(cmd)} exceeds safe-scan cap "
                                     f"({DESTRUCTIVE_SCAN_MAX_LEN}); cannot evaluate destructive patterns",
                        "reason_codes": ["input_too_large"]}
            if match is not None:
                return {**base, "decision": "deny",
                        "reasoning": f"destructive Bash pattern in: {cmd[:120]}",
                        "reason_codes": ["destructive_command"]}

        if tool_name == "Write":
            path = args.get("file_path", "")
            if any(path.startswith(p) for p in PROTECTED_PATH_PREFIXES):
                return {**base, "decision": "deny",
                        "reasoning": f"write to protected system path: {path}",
                        "reason_codes": ["protected_path"]}

        return {**base, "decision": "allow"}

    if method in INFORMATIONAL_METHODS:
        return {**base, "decision": "allow"}

    return {**base, "decision": "deny",
            "reasoning": f"unknown method: {method}",
            "reason_codes": ["unknown_method"]}


# ----- Request dispatch -----

def handle_request(request: dict) -> dict:
    method = request.get("method", "")
    request_id = request.get("id")
    params = request.get("params") or {}
    meta = params.get("metadata") or {}
    session_id = meta.get("session_id") or ""
    acs_request_id = params.get("request_id", "")
    timestamp = params.get("timestamp", "")

    # Schema-validate the envelope (if jsonschema + ACS_SPEC_DIR available).
    # Defense in depth: catches malformed envelopes from a buggy adapter
    # or hostile input before they reach policy code. system/ping and
    # handshake/hello are exempt because their payload shapes differ
    # (handshake bootstraps the wire and ping is a transport primitive).
    if (_SPEC_VALIDATION_AVAILABLE
            and method not in ("system/ping", "handshake/hello")):
        errors = list(_REQUEST_ENVELOPE_VALIDATOR.iter_errors(request))
        if errors:
            paths = "; ".join(
                f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
                for e in errors[:5]
            )
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32600,
                              "message": f"Invalid Request: envelope failed schema: {paths}"}}

    # system/ping and handshake/hello are exempt from signature/chain/replay
    # constraints per §13 (ping) and §4.1 (handshake bootstraps signing).
    if method == "system/ping":
        result = evaluate_ping(params, acs_request_id)
        envelope = {"jsonrpc": "2.0", "id": request_id, "result": result}
        return envelope

    if method == "handshake/hello":
        try:
            result = evaluate_handshake(params, acs_request_id)
        except GuardianError as e:
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": e.code, "message": e.message}}
        envelope = {"jsonrpc": "2.0", "id": request_id, "result": result}
        if _hmac_secret():
            sign_envelope(envelope, session_id=session_id)
        return envelope

    # Standard hook traffic — full pipeline
    try:
        check_signature(request, session_id)
        check_skew(timestamp)
        check_replay(session_id, acs_request_id)
    except GuardianError as e:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": e.code, "message": e.message}}

    # Compute chain entry BEFORE evaluating, then include head in result.
    payload_canonical = jcs_canonicalize(params).decode("utf-8")
    chain_hash = append_to_chain(session_id, method, acs_request_id, payload_canonical, timestamp)

    try:
        result = evaluate_step(method, params, acs_request_id, chain_hash)
    except GuardianError as e:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": e.code, "message": e.message}}

    envelope = {"jsonrpc": "2.0", "id": request_id, "result": result}
    if _hmac_secret():
        sign_envelope(envelope, session_id=session_id)
    return envelope


# ----- HTTP transport -----

class GuardianHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        # Reject oversized requests before reading the body. Defends
        # against a DoS attacker who sets Content-Length to a huge value
        # and expects us to allocate that much. MAX_REQUEST_BODY_BYTES
        # matches the handshake's advertised max_payload_size_bytes.
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600, "message": "Invalid Content-Length"}})
            return
        if length > MAX_REQUEST_BODY_BYTES:
            self._respond(413, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32600,
                                          "message": f"Request body {length} bytes exceeds {MAX_REQUEST_BODY_BYTES} cap"}})
            return
        body = self.rfile.read(length).decode("utf-8")
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"jsonrpc": "2.0", "id": None,
                                "error": {"code": -32700, "message": "Parse error"}})
            return

        method = request.get("method", "")
        params = request.get("params") or {}
        meta = params.get("metadata") or {}
        sys.stderr.write(
            f"[guardian] {method} session={meta.get('session_id', '?')[:8]} "
            f"req={params.get('request_id', '?')[:8]}\n"
        )
        sys.stderr.flush()

        response = handle_request(request)
        self._respond(200, response)

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    # §10 baseline integrity: refuse to start without a signing secret
    # unless the operator explicitly opted into dev mode.
    if not load_hmac_secret() and os.environ.get("ACS_DEV_MODE", "0") != "1":
        sys.stderr.write(
            "[guardian] REFUSING TO START: no signing secret configured.\n"
            "  Configure one of:\n"
            "    ACS_HMAC_SECRET_FILE=/path/to/key   (preferred; chmod 600)\n"
            "    ACS_HMAC_SECRET=<hex>               (env-var fallback)\n"
            "  Generate a key:\n"
            "    openssl rand -hex 32 > /etc/acs/hmac.key && chmod 600 /etc/acs/hmac.key\n"
            "  For local development without a secret (NON-CONFORMANT per §10):\n"
            "    ACS_DEV_MODE=1\n"
        )
        return 1

    if not load_hmac_secret():
        sys.stderr.write(
            "[guardian] WARNING: running in ACS_DEV_MODE — envelope signing disabled.\n"
            "  ACS-Core baseline integrity (§10) is NOT satisfied.\n"
        )

    class ReusableServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with ReusableServer((args.host, args.port), GuardianHandler) as httpd:
        sys.stderr.write(f"[guardian] listening on {args.host}:{args.port}\n")
        sys.stderr.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
