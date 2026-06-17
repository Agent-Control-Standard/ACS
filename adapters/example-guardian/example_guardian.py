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
"""
from __future__ import annotations

import argparse
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
    derive_session_key,
    iso8601_now,
    jcs_canonicalize,
    load_hmac_secret,
    parse_iso8601,
    sign_envelope,
    verify_signature,
)

import datetime


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
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive\s+--force|--force\s+--recursive)\b.*\s+(/|~|\$HOME)\b", re.IGNORECASE),
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


# ----- Per-session state (replay + chain) -----

class SessionState:
    """Holds the rolling chain head and replay protection per session_id."""

    def __init__(self) -> None:
        self.previous_hash: str | None = None  # None for the first entry (§8.1)
        self.seen_request_ids: set[str] = set()
        self.seen_nonces: set[str] = set()
        self.lock = threading.Lock()


class GuardianState:
    """Process-global state. Sessions keyed by metadata.session_id."""

    def __init__(self) -> None:
        self.sessions: dict[str, SessionState] = {}
        self.lock = threading.Lock()

    def get(self, session_id: str) -> SessionState:
        with self.lock:
            st = self.sessions.get(session_id)
            if st is None:
                st = SessionState()
                self.sessions[session_id] = st
            return st


STATE = GuardianState()


# ----- Helpers -----

def _matches_destructive_bash(cmd: str) -> re.Pattern | None:
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
        if request_id in st.seen_request_ids:
            raise GuardianError(-32005, f"REPLAY_DETECTED: request_id {request_id} already seen in session")
        st.seen_request_ids.add(request_id)


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
            cmd = args.get("command", "")
            if _matches_destructive_bash(cmd) is not None:
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
        length = int(self.headers.get("Content-Length", "0"))
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
