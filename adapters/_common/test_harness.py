"""
Shared test harness for ACS adapter tests.

Test files across `adapters/` (and `adapters/<adapter>/tests/`) have
historically duplicated ~50 lines of boilerplate each: free-port
allocation, Guardian-spawn waiting, envelope construction, schema
validation, ref-resolver setup. This module is the single home for
those helpers — import what you need rather than redefining.

Usage from any test file:

    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
    from test_harness import (
        free_port, wait_port,
        make_envelope, validate_request_envelope, validate_response_envelope,
        spawn_guardian, ProgrammableGuardian,
    )

The harness has no opinion on `unittest.TestCase` vs other runners —
it's pure functions and a context manager. Plug it into whatever
framework you're using.

The harness exists today (created with the spec_compliance cleanup);
older test files still have inline duplicates. Migration is opt-in:
when you next touch a test file, swap its inline `_free_port` /
`_wait` / `_make_envelope` for imports from here.
"""
from __future__ import annotations

import contextlib
import datetime
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator

# Bootstrap acs_common from the sibling location so callers don't need to
# import both manually.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import acs_common  # noqa: E402


# ────────────────────────────────────────────────────────────────────
# Port + readiness
# ────────────────────────────────────────────────────────────────────

def free_port() -> int:
    """Return an unused TCP port on 127.0.0.1."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(host: str, port: int, *, timeout: float = 5.0) -> None:
    """Block until something is listening on host:port, or raise."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server not up on {host}:{port} after {timeout}s")


# ────────────────────────────────────────────────────────────────────
# Envelope construction
# ────────────────────────────────────────────────────────────────────

def make_envelope(
    method: str,
    payload: dict | None = None,
    *,
    session_id: str | None = None,
    request_id: str | None = None,
    timestamp: str | None = None,
    agent_id: str = "test",
    platform: str = "test",
    sign_with_secret: str | bytes | None = None,
) -> dict:
    """Build a canonical request envelope ready for the wire.

    Pass `sign_with_secret` to attach an HMAC-SHA256 signature using
    the same HKDF-per-session-key derivation the real adapters use.
    Pass None to leave the envelope unsigned (used for handshake/hello,
    system/ping, or to test the unsigned-rejection path).
    """
    sid = session_id or str(uuid.uuid4())
    env = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": "0.1.0",
            "request_id": request_id or str(uuid.uuid4()),
            "timestamp": timestamp or acs_common.iso8601_now(),
            "metadata": {
                "agent_id": agent_id,
                "session_id": sid,
                "platform": platform,
            },
            "payload": payload or {},
        },
    }
    if sign_with_secret is not None:
        secret = sign_with_secret.encode() if isinstance(sign_with_secret, str) else sign_with_secret
        key = acs_common.derive_session_key(secret, sid)
        acs_common.sign_envelope(env, key=key, session_id=sid)
    return env


def claude_code_event(hook_event_name: str, *, session_id: str | None = None,
                       **extra: Any) -> dict:
    """Build a Claude Code hook event matching the framework's stdin schema.

    Use this for `subprocess`-spawning adapter tests so every fixture
    has the same shape.
    """
    base = {
        "session_id": session_id or str(uuid.uuid4()),
        "transcript_path": "/tmp/test_transcript.jsonl",
        "cwd": "/tmp/test_work",
        "hook_event_name": hook_event_name,
    }
    if hook_event_name in ("PreToolUse", "PostToolUse", "Stop"):
        base["permission_mode"] = "default"
    base.update(extra)
    return base


# ────────────────────────────────────────────────────────────────────
# Schema validation
# ────────────────────────────────────────────────────────────────────

def _default_spec_dir() -> Path:
    """Resolve the canonical schema directory. Override with ACS_SPEC_DIR.

    Defaults to the in-repo schemas (this file lives at adapters/_common/,
    schemas at specification/v0.1.0/ two directories up) so tests run from
    a fresh clone and validate against the schemas in the PR under review.
    """
    return Path(os.environ.get(
        "ACS_SPEC_DIR",
        str(Path(__file__).resolve().parents[2] / "specification" / "v0.1.0")))


def build_local_resolver(schema_name: str, *, spec_dir: Path | None = None):
    """Return (schema_dict, RefResolver) for `schema_name` under spec_dir.

    Populates the resolver's `store` so `$ref` to sibling schemas
    resolves locally (no network round-trip to acs.org).
    """
    from jsonschema.validators import RefResolver
    spec_dir = spec_dir or _default_spec_dir()
    store: dict[str, dict] = {}
    for path in spec_dir.glob("*.json"):
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if "$id" in doc:
            store[doc["$id"]] = doc
        store[path.as_uri()] = doc
    hooks_dir = spec_dir / "hooks"
    if hooks_dir.exists():
        for path in hooks_dir.glob("*.json"):
            try:
                doc = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            if "$id" in doc:
                store[doc["$id"]] = doc
            store[path.as_uri()] = doc

    schema_path = spec_dir / schema_name
    schema = json.loads(schema_path.read_text())
    resolver = RefResolver(
        base_uri=schema_path.as_uri(),
        referrer=schema,
        store=store,
    )
    return schema, resolver


def _validate(envelope: dict, schema_name: str,
              spec_dir: Path | None = None) -> list[str]:
    from jsonschema import Draft202012Validator
    schema, resolver = build_local_resolver(schema_name, spec_dir=spec_dir)
    validator = Draft202012Validator(
        schema, resolver=resolver,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    return [
        f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(envelope)
    ]


def validate_request_envelope(envelope: dict, *,
                               spec_dir: Path | None = None) -> list[str]:
    """Validate against request-envelope.json. Returns list of error
    messages; empty list means valid."""
    return _validate(envelope, "request-envelope.json", spec_dir=spec_dir)


def validate_response_envelope(envelope: dict, *,
                                spec_dir: Path | None = None) -> list[str]:
    """Validate against response-envelope.json. Returns list of error
    messages; empty list means valid."""
    return _validate(envelope, "response-envelope.json", spec_dir=spec_dir)


def validate_hook_payload(payload: dict, hook_schema: str, *,
                           spec_dir: Path | None = None) -> list[str]:
    """Validate a hook payload (e.g., `hooks/tool-call-request.json`).
    Returns list of error messages; empty list means valid."""
    return _validate(payload, f"hooks/{hook_schema}", spec_dir=spec_dir)


# ────────────────────────────────────────────────────────────────────
# HTTP helpers
# ────────────────────────────────────────────────────────────────────

def post_envelope(url: str, envelope: dict, *, timeout: float = 5.0) -> dict:
    """POST an envelope to a Guardian URL and return the parsed response.

    Raises urllib errors if the Guardian is unreachable — callers can
    catch to test fail-posture behavior.
    """
    body = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ────────────────────────────────────────────────────────────────────
# Guardian lifecycle
# ────────────────────────────────────────────────────────────────────

GUARDIAN_SCRIPT = _HERE.parent / "example-guardian" / "example_guardian.py"


@contextlib.contextmanager
def spawn_guardian(*, port: int | None = None,
                    hmac_secret: str | None = None,
                    dev_mode: bool | None = None,
                    state_dir: str | None = None,
                    extra_env: dict | None = None) -> Iterator[tuple[subprocess.Popen, str]]:
    """Spawn an example_guardian subprocess; yield (process, url); clean up.

    Usage:
        with spawn_guardian(hmac_secret="test") as (proc, url):
            resp = post_envelope(url, env)
            ...
    """
    port = port or free_port()
    env = os.environ.copy()
    if hmac_secret is not None:
        env["ACS_HMAC_SECRET"] = hmac_secret
        env.pop("ACS_DEV_MODE", None)
    else:
        env["ACS_DEV_MODE"] = "1" if dev_mode is not False else "0"
        env.pop("ACS_HMAC_SECRET", None)
    env.pop("ACS_HMAC_SECRET_FILE", None)
    if state_dir:
        env["ACS_GUARDIAN_STATE_DIR"] = state_dir
    else:
        # Default to an ephemeral state dir so tests don't cross-contaminate
        env["ACS_GUARDIAN_STATE_DIR"] = tempfile.mkdtemp(prefix="acs-test-state-")
    if extra_env:
        env.update(extra_env)

    proc = subprocess.Popen(
        [sys.executable, str(GUARDIAN_SCRIPT), "--port", str(port)],
        env=env,
        stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
    )
    try:
        wait_port("127.0.0.1", port)
        yield proc, f"http://127.0.0.1:{port}/acs"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
        # Clean ephemeral state dir if we created it
        if not state_dir:
            import shutil
            shutil.rmtree(env["ACS_GUARDIAN_STATE_DIR"], ignore_errors=True)


# ────────────────────────────────────────────────────────────────────
# Programmable Guardian — for tests that need to control responses.
# ────────────────────────────────────────────────────────────────────
#
# `spawn_guardian` runs the REAL example_guardian process — useful for
# integration tests against the production code path. For unit tests
# that need to force specific dispositions (modify, ask, defer) or
# delays, use ProgrammableGuardian: an in-process HTTP server you can
# configure handler-by-handler.

class ProgrammableGuardian:
    """Test Guardian whose response can be programmed per method.

    Records every received request and every sent response so tests
    can assert on the wire-level exchange. By default verifies HMAC
    signatures (using TEST_HMAC_SECRET) and returns allow for every
    method. Replace `handlers[method]` with a callable returning a
    result dict (or an error dict with `code` + `message`) to customize.
    """

    DEFAULT_TEST_HMAC_SECRET = "shared-test-harness-secret-not-for-production"

    def __init__(self, *, hmac_secret: str | None = None,
                  sign_responses: bool = True) -> None:
        import http.server
        self.hmac_secret = hmac_secret or self.DEFAULT_TEST_HMAC_SECRET
        self.sign_responses = sign_responses
        self.received: list[dict] = []
        self.sent: list[dict] = []
        self.lock = threading.Lock()
        self.handlers: dict[str, Callable[[dict], dict]] = {
            "handshake/hello": self._default_handshake,
            "__default__":     self._default_allow,
        }
        self.delay_s: float = 0.0
        # Optional callback(raw_bytes, parsed_dict) run on every received
        # request before the response is built. CaptureGuardian uses it
        # as the schema-validation oracle. None = no-op. Any exception it
        # raises is recorded here (not swallowed) so a validator bug is
        # loud, not silent.
        self.on_request = None
        self.on_request_errors: list[str] = []
        self._http = http.server
        # Bind port 0 and read the OS-assigned port — no bind-then-release
        # race (free_port() closes the socket before the server rebinds,
        # which flakes under runner contention; PR #22 review). free_port()
        # remains for SUBPROCESS guardians that need a port as an argv.
        self._server = self._http.HTTPServer(
            ("127.0.0.1", 0), self._make_handler_cls())
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/acs"

    def start(self) -> None:
        self._thread.start()
        wait_port("127.0.0.1", self.port)

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def reset(self) -> None:
        with self.lock:
            self.received.clear()
            self.sent.clear()

    def methods_seen(self) -> list[str]:
        with self.lock:
            return [r.get("method", "") for r in self.received]

    def last_envelope(self) -> dict | None:
        with self.lock:
            return self.received[-1] if self.received else None

    def envelopes_for(self, method: str) -> list[dict]:
        with self.lock:
            return [r for r in self.received if r.get("method") == method]

    # ─── Default handlers ───

    def _default_handshake(self, req: dict) -> dict:
        return {
            "type": "final", "acs_version": "0.1.0",
            "request_id": req["params"]["request_id"],
            "decision": "allow",
            "payload": {
                "negotiated_version": "0.1.0",
                "methods_evaluated": req["params"]["payload"].get("methods_implemented", []),
                "selected_transport": "http",
                "signature_algorithms_supported": ["HMAC-SHA256"],
                "timeout_config": {"default_ms": 5000},
                "skew_window_ms": 300000,
                "on_decision_failure": "proceed",
                "profiles_accepted": ["acs-core"],
            },
        }

    def _default_allow(self, req: dict) -> dict:
        return {
            "type": "final", "acs_version": "0.1.0",
            "request_id": req["params"]["request_id"],
            "decision": "allow",
            "chain_hash": "0" * 64,
        }

    def _make_handler_cls(self):
        guardian = self

        class Handler(self._http.BaseHTTPRequestHandler):
            def do_POST(self_h):  # noqa: N802
                length = int(self_h.headers.get("Content-Length", "0"))
                raw = self_h.rfile.read(length)
                req = json.loads(raw.decode())
                with guardian.lock:
                    guardian.received.append(req)
                # Optional raw-capture hook: subclasses (CaptureGuardian)
                # set this to validate the UNMODIFIED bytes against the
                # canonical schemas, so the schema files — not this
                # server's leniency — are the oracle (PR #22 emission
                # review). No-op for plain ProgrammableGuardian users.
                # An exception here is NOT swallowed silently — a
                # schema-load or validator bug that made a capture look
                # valid would defeat the whole point (PR #22 emission
                # re-review). It is recorded so assert_all_valid() fails,
                # while the wire stays alive so the adapter completes.
                if guardian.on_request is not None:
                    try:
                        guardian.on_request(raw, req)
                    except Exception as e:  # noqa: BLE001
                        with guardian.lock:
                            guardian.on_request_errors.append(repr(e))
                if guardian.delay_s > 0:
                    time.sleep(guardian.delay_s)

                method = req.get("method", "")
                # system/ping is the ONLY signature-exempt method (§13).
                # The handshake is signed like everything else — the HMAC
                # key derives from pre-shared secret + session_id, both
                # known pre-handshake (PR #22 second review).
                if method != "system/ping":
                    sid = req.get("params", {}).get("metadata", {}).get("session_id", "")
                    key = acs_common.derive_session_key(
                        guardian.hmac_secret.encode(), sid)
                    if not acs_common.verify_signature(req, key=key, session_id=sid):
                        self_h._reply({
                            "jsonrpc": "2.0", "id": req.get("id"),
                            "error": {"code": -32004, "message": "SIGNATURE_INVALID"},
                        })
                        return

                handler = guardian.handlers.get(method, guardian.handlers["__default__"])
                result_or_error = handler(req)
                if "code" in result_or_error and "message" in result_or_error:
                    resp = {"jsonrpc": "2.0", "id": req.get("id"),
                            "error": result_or_error}
                else:
                    resp = {"jsonrpc": "2.0", "id": req.get("id"),
                            "result": result_or_error}
                    if guardian.sign_responses:
                        sid = req["params"]["metadata"]["session_id"]
                        key = acs_common.derive_session_key(
                            guardian.hmac_secret.encode(), sid)
                        acs_common.sign_envelope(resp, key=key, session_id=sid)
                self_h._reply(resp)

            def _reply(self_h, resp: dict):
                with guardian.lock:
                    guardian.sent.append(resp)
                body = json.dumps(resp).encode()
                self_h.send_response(200)
                self_h.send_header("Content-Type", "application/json")
                self_h.send_header("Content-Length", str(len(body)))
                self_h.end_headers()
                self_h.wfile.write(body)

            def log_message(self_h, *a, **kw):
                return

        return Handler
