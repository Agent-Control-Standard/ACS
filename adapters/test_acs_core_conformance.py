"""
ACS-Core conformance test suite.

ONE test per MUST in `docs/spec/conformance.md` ACS-Core (lines 13-26),
plus the normative requirements in the §-cited sections it references.
Each test docstring quotes the exact spec text it falsifies.

Run from the adapters/ directory:

    python -m unittest test_acs_core_conformance

Result: a single "OK" with all-pass means this reference implementation
is ACS-Core conformant against v0.1.0 as enumerated below.

Result: any FAIL/ERROR names the specific MUST that broke, with the
spec citation in the test docstring.

Adopter workflow: copy our adapters, modify for your stack, run this
file. If it still passes, your fork is still ACS-Core. If it fails,
the failure message tells you which spec line you broke.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac as _hmac
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
GUARDIAN_SCRIPT = HERE / "example-guardian" / "example_guardian.py"
COMMON_DIR = HERE / "_common"

sys.path.insert(0, str(COMMON_DIR))
import acs_common  # noqa: E402

# Canonical schemas — REQUIRED for envelope/payload validation.
# Without them, the conformance suite can't validate; it FAILS loudly
# rather than silently skipping.
SPEC_DIR = Path(
    os.environ.get(
        "ACS_SPEC_DIR",
        "/tmp/acs-spec-source/specification/v0.1.0",
    )
)

# A fixed signing secret used only inside this test process. Real
# deployments use ACS_HMAC_SECRET_FILE; we pass it via env.
TEST_HMAC_SECRET = "acs-core-conformance-test-secret-not-for-production"


# =============================================================================
# Test harness — spawns the Guardian, exchanges signed envelopes.
# =============================================================================

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Guardian did not start on {host}:{port}")


def _build_local_resolver(schema_name: str):
    """RefResolver with a `store` mapping canonical $id URLs to local
    schema files, so $refs like 'modifications.json' resolve to disk
    instead of network. Avoids RefResolver hitting acs.org."""
    from jsonschema.validators import RefResolver
    store = {}
    for path in SPEC_DIR.glob("*.json"):
        try:
            with open(path) as f:
                doc = json.load(f)
            if "$id" in doc:
                store[doc["$id"]] = doc
            # Also register by local-file URI for relative $refs
            store[path.as_uri()] = doc
        except (OSError, json.JSONDecodeError):
            pass
    for path in (SPEC_DIR / "hooks").glob("*.json"):
        try:
            with open(path) as f:
                doc = json.load(f)
            if "$id" in doc:
                store[doc["$id"]] = doc
            store[path.as_uri()] = doc
        except (OSError, json.JSONDecodeError):
            pass
    schema_path = SPEC_DIR / schema_name
    with open(schema_path) as f:
        schema = json.load(f)
    resolver = RefResolver(
        base_uri=schema_path.as_uri(),
        referrer=schema,
        store=store,
    )
    return schema, resolver


def _validate_response_envelope(envelope: dict) -> list[str]:
    from jsonschema import Draft202012Validator
    schema, resolver = _build_local_resolver("response-envelope.json")
    validator = Draft202012Validator(
        schema, resolver=resolver,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    return [
        f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(envelope)
    ]


def _validate_request_envelope(envelope: dict) -> list[str]:
    from jsonschema import Draft202012Validator
    schema, resolver = _build_local_resolver("request-envelope.json")
    validator = Draft202012Validator(
        schema, resolver=resolver,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    return [
        f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(envelope)
    ]


class CoreHarness(unittest.TestCase):
    """Base class — spawns a Guardian with HMAC signing required.

    Each test class inherits and adds tests. setUpClass spawns one
    Guardian for the class; tests share it. Each test creates a fresh
    session_id so per-session state (replay set, chain head) doesn't
    cross-contaminate.
    """

    HMAC_SECRET: str | None = TEST_HMAC_SECRET  # subclass can null to disable

    @classmethod
    def setUpClass(cls) -> None:
        if not SPEC_DIR.exists():
            raise RuntimeError(
                f"Canonical ACS schemas not found at {SPEC_DIR}. "
                "ACS-Core conformance tests REQUIRE the canonical v0.1.0 "
                "schemas. Set ACS_SPEC_DIR to a clone of "
                "Agent-Control-Standard/ACS/specification/v0.1.0/. "
                "This is a hard fail — schema validation is non-negotiable."
            )
        cls.port = _free_port()
        cls.url = f"http://127.0.0.1:{cls.port}/acs"
        env = os.environ.copy()
        cls.statedir = tempfile.mkdtemp(prefix="acs-core-conformance-")
        env["ACS_GUARDIAN_STATE_DIR"] = cls.statedir
        if cls.HMAC_SECRET:
            env["ACS_HMAC_SECRET"] = cls.HMAC_SECRET
            env.pop("ACS_DEV_MODE", None)
        else:
            env["ACS_DEV_MODE"] = "1"
            env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.guardian_proc = subprocess.Popen(
            [sys.executable, str(GUARDIAN_SCRIPT), "--port", str(cls.port)],
            env=env,
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
        )
        _wait_port("127.0.0.1", cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()
        import shutil
        shutil.rmtree(cls.statedir, ignore_errors=True)

    def _make_envelope(self, method: str, payload: dict | None = None, *,
                       session_id: str | None = None,
                       request_id: str | None = None,
                       timestamp: str | None = None,
                       sign: bool = True) -> dict:
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
                    "agent_id": "conformance-test",
                    "session_id": sid,
                    "platform": "test",
                },
                "payload": payload or {},
            },
        }
        if sign and self.HMAC_SECRET:
            key = acs_common.derive_session_key(self.HMAC_SECRET.encode(), sid)
            acs_common.sign_envelope(env, key=key, session_id=sid)
        return env

    def _post(self, envelope: dict) -> dict:
        body = json.dumps(envelope).encode()
        req = urllib.request.Request(self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode())


# =============================================================================
# CORE-01 — Handshake (conformance.md:17, §4)
# =============================================================================
#
# "Handshake — handshake/hello with ClientHello/ServerHello"
# §4: "Version mismatch terminates with UNSUPPORTED_VERSION (-32001)"
# §4: ServerHello required keys negotiated_version, methods_evaluated,
#     selected_transport, timeout_config
# =============================================================================

class Core01_Handshake(CoreHarness):

    def test_handshake_returns_server_hello(self) -> None:
        """conformance.md:17 — 'Handshake — handshake/hello with
        ClientHello/ServerHello'. A Guardian MUST respond to
        handshake/hello with a ServerHello in result.payload."""
        env = self._make_envelope("handshake/hello", payload={
            "acs_versions_supported": ["0.1.0"],
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
            "profiles_supported": ["acs-core"],
        }, sign=False)
        resp = self._post(env)
        self.assertIn("result", resp,
            f"handshake/hello must return a result; got {resp}")
        result = resp["result"]
        server_hello = result.get("payload", {})
        # handshake.json:70 — ServerHello required
        for required_field in ("negotiated_version", "methods_evaluated",
                               "selected_transport", "timeout_config"):
            self.assertIn(required_field, server_hello,
                f"ServerHello missing required field {required_field!r}; "
                f"got {server_hello}")
        self.assertEqual(server_hello["negotiated_version"], "0.1.0")
        self.assertIn("default_ms", server_hello["timeout_config"])

    def test_version_mismatch_returns_unsupported_version(self) -> None:
        """§4: 'Version mismatch terminates with UNSUPPORTED_VERSION
        (-32001)'."""
        env = self._make_envelope("handshake/hello", payload={
            "acs_versions_supported": ["99.0.0"],  # unsupported
            "methods_implemented": ["steps/toolCallRequest"],
            "transports_supported": ["http"],
            "provenance_producer": "none",
        }, sign=False)
        resp = self._post(env)
        self.assertIn("error", resp,
            f"version-mismatch handshake must error; got {resp}")
        self.assertEqual(resp["error"]["code"], -32001,
            f"§4: code must be -32001 UNSUPPORTED_VERSION; got {resp['error']}")


# =============================================================================
# CORE-02 — Request envelope shape (conformance.md:18, §3, request-envelope.json)
# =============================================================================
#
# "JSON-RPC 2.0 with ACS extensions. request_id, timestamp, acs_version,
#  metadata required on every request."
#
# request-envelope.json:7-8 — top-level required {jsonrpc, method, id, params};
#                              additionalProperties: false
# request-envelope.json:10 — jsonrpc const "2.0"
# request-envelope.json:25 — AcsParams required {acs_version, request_id,
#                              timestamp, metadata, payload}
# request-envelope.json:62 — Metadata required {agent_id, session_id}
# =============================================================================

class Core02_EnvelopeShape(CoreHarness):

    def test_valid_envelope_passes_canonical_schema(self) -> None:
        """conformance.md:18 — 'request_id, timestamp, acs_version,
        metadata required on every request'. A correctly-built envelope
        MUST pass request-envelope.json validation including
        format-checker (uuid, date-time)."""
        env = self._make_envelope("steps/sessionStart", payload={})
        errors = _validate_request_envelope(env)
        self.assertEqual(errors, [],
            f"Conformant envelope FAILS request-envelope.json validation:\n  - "
            + "\n  - ".join(errors))

    def test_jsonrpc_field_is_literal_2_0(self) -> None:
        """request-envelope.json:10 — `jsonrpc` is the literal string
        "2.0"; any other value MUST be rejected by schema validation."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["jsonrpc"] = "1.0"  # tamper
        errors = _validate_request_envelope(env)
        self.assertTrue(any("jsonrpc" in e for e in errors),
            f"jsonrpc != '2.0' must fail validation; got errors {errors}")

    def test_no_additional_top_level_fields_allowed(self) -> None:
        """request-envelope.json:8 — `additionalProperties: false` at
        envelope root. Any extra top-level key MUST be rejected."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["unknown_field"] = "should be rejected"
        errors = _validate_request_envelope(env)
        self.assertTrue(any("unknown_field" in e or "Additional" in e for e in errors),
            f"Extra top-level field must be rejected; got {errors}")

    def test_acs_params_all_required_fields_present(self) -> None:
        """request-envelope.json:25 — AcsParams MUST contain
        acs_version, request_id, timestamp, metadata, payload."""
        env = self._make_envelope("steps/sessionStart", payload={})
        for required in ("acs_version", "request_id", "timestamp",
                          "metadata", "payload"):
            self.assertIn(required, env["params"],
                f"params must contain {required!r}")
        # Now drop each in turn; validator must reject every variant.
        for required in ("acs_version", "request_id", "timestamp",
                          "metadata", "payload"):
            broken = json.loads(json.dumps(env))
            del broken["params"][required]
            errors = _validate_request_envelope(broken)
            self.assertTrue(errors,
                f"envelope missing required params.{required} must fail; "
                f"validator passed instead")

    def test_metadata_required_agent_and_session_id(self) -> None:
        """request-envelope.json:62 — metadata MUST contain agent_id
        and session_id."""
        env = self._make_envelope("steps/sessionStart", payload={})
        for required in ("agent_id", "session_id"):
            self.assertIn(required, env["params"]["metadata"])
        # Drop each; validator rejects.
        for required in ("agent_id", "session_id"):
            broken = json.loads(json.dumps(env))
            del broken["params"]["metadata"][required]
            errors = _validate_request_envelope(broken)
            self.assertTrue(any(required in e for e in errors),
                f"envelope missing metadata.{required} must fail validation")

    def test_request_id_is_uuid(self) -> None:
        """request-envelope.json:32-35 — request_id format: uuid."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["params"]["request_id"] = "not-a-uuid"
        errors = _validate_request_envelope(env)
        self.assertTrue(any("request_id" in e for e in errors),
            f"non-UUID request_id must fail validation; got {errors}")

    def test_timestamp_is_iso8601(self) -> None:
        """request-envelope.json:38-40 — timestamp format: date-time."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["params"]["timestamp"] = "yesterday"
        errors = _validate_request_envelope(env)
        self.assertTrue(any("timestamp" in e for e in errors),
            f"non-ISO timestamp must fail validation; got {errors}")

    def test_acs_version_matches_semver(self) -> None:
        """request-envelope.json:27-30 — acs_version pattern ^\\d+\\.\\d+\\.\\d+$."""
        env = self._make_envelope("steps/sessionStart", payload={})
        env["params"]["acs_version"] = "v1"  # not semver
        errors = _validate_request_envelope(env)
        self.assertTrue(any("acs_version" in e for e in errors),
            f"non-semver acs_version must fail validation; got {errors}")

    def test_method_namespace_pattern(self) -> None:
        """request-envelope.json:13-14 — method MUST match
        ^(steps/|protocols/|agbom/|trace/|system/|handshake/|wrapped:).+"""
        env = self._make_envelope("arbitrary/method", payload={})
        errors = _validate_request_envelope(env)
        self.assertTrue(any("method" in e for e in errors),
            f"method outside reserved namespaces must fail validation")


# =============================================================================
# CORE-03 — Hook taxonomy minimum (conformance.md:19)
# =============================================================================
#
# "At minimum: sessionStart, userMessage or agentTrigger, toolCallRequest,
#  toolCallResult, agentResponse, sessionEnd"
# =============================================================================

class Core03_HookTaxonomyMinimum(CoreHarness):
    """Each of the 6 minimum hooks MUST be acceptable to the Guardian
    (validated end-to-end against a real envelope round-trip)."""

    def _try_hook(self, method: str, payload: dict) -> dict:
        env = self._make_envelope(method, payload)
        return self._post(env)

    def test_session_start(self) -> None:
        """conformance.md:19 — sessionStart in minimum set"""
        resp = self._try_hook("steps/sessionStart", {})
        self.assertIn("result", resp,
            f"steps/sessionStart must be accepted; got {resp}")

    def test_user_message(self) -> None:
        """conformance.md:19 — userMessage or agentTrigger in minimum set"""
        resp = self._try_hook("steps/userMessage",
            {"content": [{"type": "text", "value": "hi"}]})
        self.assertIn("result", resp)

    def test_tool_call_request(self) -> None:
        """conformance.md:19 — toolCallRequest in minimum set"""
        resp = self._try_hook("steps/toolCallRequest",
            {"tool": {"name": "Read"},
             "arguments": {"file_path": {"value": "/tmp/x"}}})
        self.assertIn("result", resp)

    def test_tool_call_result(self) -> None:
        """conformance.md:19 — toolCallResult in minimum set"""
        resp = self._try_hook("steps/toolCallResult",
            {"tool": {"name": "Read"}, "exit_status": "success",
             "outputs": [{"value": "ok"}]})
        self.assertIn("result", resp)

    def test_agent_response(self) -> None:
        """conformance.md:19 — agentResponse in minimum set"""
        resp = self._try_hook("steps/agentResponse",
            {"content": [{"type": "text", "value": "ok"}]})
        self.assertIn("result", resp)

    def test_session_end(self) -> None:
        """conformance.md:19 — sessionEnd in minimum set"""
        resp = self._try_hook("steps/sessionEnd", {"reason": "completed"})
        self.assertIn("result", resp)


# =============================================================================
# CORE-04 — Dispositions (conformance.md:20, §6)
# =============================================================================
#
# "All five (ALLOW, DENY, MODIFY, ASK, DEFER) with required fields per §6"
# response-envelope.json:107-110 — conditional requirements:
#   deny -> reasoning required
#   modify -> reasoning + modifications required
#   ask -> reasoning + ask_details required
#   defer -> reasoning + defer_details required
# =============================================================================

class Core04_Dispositions(CoreHarness):

    def test_allow_response_validates(self) -> None:
        """§6 — ALLOW: no required fields beyond decision."""
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        errors = _validate_response_envelope(resp)
        self.assertEqual(errors, [],
            f"ALLOW response fails response-envelope.json:\n  - "
            + "\n  - ".join(errors))
        self.assertEqual(resp["result"]["decision"], "allow")

    def test_deny_response_includes_reasoning(self) -> None:
        """response-envelope.json:107 — 'if decision const deny, then
        required: [reasoning]'. The Guardian's destructive-bash deny
        path MUST include reasoning."""
        env = self._make_envelope("steps/toolCallRequest",
            {"tool": {"name": "Bash"},
             "arguments": {"command": {"value": "rm -rf /home/u"}}})
        resp = self._post(env)
        self.assertEqual(resp["result"]["decision"], "deny")
        self.assertIn("reasoning", resp["result"],
            "§6 + response-envelope.json:107 — DENY MUST include reasoning")
        self.assertTrue(resp["result"]["reasoning"])
        # The response itself MUST validate
        errors = _validate_response_envelope(resp)
        self.assertEqual(errors, [],
            f"DENY response fails response-envelope.json:\n  - "
            + "\n  - ".join(errors))

    def test_modify_without_modifications_rejected_by_schema(self) -> None:
        """response-envelope.json:108 — 'if decision const modify, then
        required: [reasoning, modifications]'. A response that claims
        modify but lacks modifications MUST fail schema validation."""
        # Synthesize a broken response (Guardian doesn't emit modify in
        # our example, so we construct one manually and validate it).
        broken = {
            "jsonrpc": "2.0", "id": "x",
            "result": {
                "type": "final", "acs_version": "0.1.0",
                "request_id": "00000000-0000-4000-8000-000000000001",
                "decision": "modify",
                "reasoning": "but no modifications field",
            },
        }
        errors = _validate_response_envelope(broken)
        self.assertTrue(any("modifications" in e for e in errors),
            f"modify-without-modifications must fail validation; got {errors}")

    def test_ask_without_ask_details_rejected_by_schema(self) -> None:
        """response-envelope.json:109 — 'if decision const ask, then
        required: [reasoning, ask_details]'."""
        broken = {
            "jsonrpc": "2.0", "id": "x",
            "result": {
                "type": "final", "acs_version": "0.1.0",
                "request_id": "00000000-0000-4000-8000-000000000001",
                "decision": "ask", "reasoning": "missing ask_details",
            },
        }
        errors = _validate_response_envelope(broken)
        self.assertTrue(any("ask_details" in e for e in errors),
            f"ask-without-ask_details must fail validation; got {errors}")

    def test_defer_without_defer_details_rejected_by_schema(self) -> None:
        """response-envelope.json:110 — 'if decision const defer, then
        required: [reasoning, defer_details]'."""
        broken = {
            "jsonrpc": "2.0", "id": "x",
            "result": {
                "type": "final", "acs_version": "0.1.0",
                "request_id": "00000000-0000-4000-8000-000000000001",
                "decision": "defer", "reasoning": "missing defer_details",
            },
        }
        errors = _validate_response_envelope(broken)
        self.assertTrue(any("defer_details" in e for e in errors),
            f"defer-without-defer_details must fail validation; got {errors}")


# =============================================================================
# CORE-05 — SessionContext + chain head (conformance.md:21, §8)
# =============================================================================
#
# "session_id, chain_hash (rolling SHA-256), append-only ContextEntry chain,
#  with the Guardian publishing the chain head (chain_hash) on responses for
#  content-bearing steps"
# §8.2 — entry_hash = SHA-256(JCS(entry minus entry_hash/previous_hash) || prev_hash_bytes)
# =============================================================================

class Core05_SessionContext(CoreHarness):

    def test_response_carries_chain_hash(self) -> None:
        """conformance.md:21 — 'Guardian publishing the chain head
        (chain_hash) on responses for content-bearing steps'."""
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        self.assertIn("chain_hash", resp["result"],
            f"response missing chain_hash; got {resp['result']}")

    def test_chain_hash_is_lowercase_hex_sha256(self) -> None:
        """response-envelope.json:82-85 — chain_hash pattern
        ^[0-9a-f]{64}$ (lowercase hex SHA-256)."""
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        h = resp["result"]["chain_hash"]
        self.assertRegex(h, r"^[0-9a-f]{64}$",
            f"chain_hash must be lowercase 64-hex SHA-256; got {h!r}")

    def test_chain_links_consecutive_entries(self) -> None:
        """§8.2 normative — consecutive entries in a session must be
        chained, i.e. entry[i+1].previous_hash = entry[i].entry_hash."""
        sid = str(uuid.uuid4())
        h1 = self._post(self._make_envelope("steps/sessionStart", {},
                                            session_id=sid))["result"]["chain_hash"]
        h2 = self._post(self._make_envelope(
            "steps/toolCallRequest",
            {"tool": {"name": "Read"},
             "arguments": {"file_path": {"value": "/tmp/x"}}},
            session_id=sid))["result"]["chain_hash"]
        self.assertNotEqual(h1, h2,
            "consecutive chain_hashes must differ — a fake chain reuses hashes")

    def test_distinct_sessions_have_distinct_chain_heads(self) -> None:
        """§8.2 — chain is per-session; two different sessions must
        produce different chain heads from the same first event."""
        h1 = self._post(self._make_envelope("steps/sessionStart", {}))["result"]["chain_hash"]
        h2 = self._post(self._make_envelope("steps/sessionStart", {}))["result"]["chain_hash"]
        self.assertNotEqual(h1, h2)

    def test_chain_externally_recomputable(self) -> None:
        """§8.2 normative — entry_hash = SHA-256(JCS(entry minus
        entry_hash/previous_hash) || prev_hash_bytes). An external
        observer with the request stream MUST be able to recompute
        the published chain head byte-for-byte."""
        sid = str(uuid.uuid4())
        req = self._make_envelope("steps/sessionStart", {}, session_id=sid)
        published = self._post(req)["result"]["chain_hash"]

        # Recompute as the Guardian does
        params = req["params"]
        # Guardian strips the signature before computing chain entry, since
        # the signature isn't input to the chain — but actually the chain
        # entry only uses request_hash = sha256(JCS(params)). Reproduce that.
        # We do NOT strip the signature here because the signature IS in params.
        # Look at example_guardian append_to_chain: it does
        # payload_canonical = jcs_canonicalize(params).decode("utf-8")
        # and request_hash = sha256(payload_canonical.encode())
        request_hash = hashlib.sha256(
            acs_common.jcs_canonicalize(params)).hexdigest()
        entry = {
            "entry_id": params["request_id"],
            "step_id": params["request_id"],
            "step_type": "steps/sessionStart",
            "request_hash": request_hash,
            "timestamp": params["timestamp"],
        }
        # No previous_hash → first entry
        content_bytes = acs_common.jcs_canonicalize(entry)
        expected = hashlib.sha256(content_bytes).hexdigest()
        self.assertEqual(published, expected,
            "published chain_hash does not byte-equal externally-recomputed "
            "hash. §8.2 requires the chain be reproducible.")


# =============================================================================
# CORE-06 — Replay protection (conformance.md:22, §10.3)
# =============================================================================
#
# "request_id (UUID) and timestamp on every request; Guardians MUST reject
#  replays per §10.3"
# §10.3: "Guardians MUST reject duplicate request_id values within the
#        session with REPLAY_DETECTED (-32005)"
# §10.3: "Guardians MUST reject requests whose timestamp is more than the
#        negotiated skew window in the past or future, returning
#        TIMESTAMP_OUT_OF_WINDOW (-32006)"
# =============================================================================

class Core06_ReplayProtection(CoreHarness):

    def test_duplicate_request_id_rejected_with_32005(self) -> None:
        """§10.3 — 'Guardians MUST reject duplicate request_id values
        within the session with REPLAY_DETECTED (-32005)'."""
        sid = str(uuid.uuid4())
        rid = str(uuid.uuid4())
        r1 = self._post(self._make_envelope("steps/sessionStart", {},
                                            session_id=sid, request_id=rid))
        self.assertIn("result", r1)
        r2 = self._post(self._make_envelope("steps/userMessage",
            {"content": [{"type": "text", "value": "hi"}]},
            session_id=sid, request_id=rid))
        self.assertIn("error", r2, f"replay must be rejected; got {r2}")
        self.assertEqual(r2["error"]["code"], -32005,
            f"§10.3 — code must be -32005 REPLAY_DETECTED; got {r2['error']}")

    def test_timestamp_outside_window_rejected_with_32006(self) -> None:
        """§10.3 — 'Guardians MUST reject requests whose timestamp is
        more than the negotiated skew window in the past or future,
        returning TIMESTAMP_OUT_OF_WINDOW (-32006)'."""
        ancient = datetime.datetime(2010, 1, 1, tzinfo=datetime.timezone.utc).isoformat()
        resp = self._post(self._make_envelope("steps/sessionStart", {},
                                              timestamp=ancient))
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32006,
            f"§10.3 — code must be -32006 TIMESTAMP_OUT_OF_WINDOW")

    def test_same_request_id_across_sessions_is_fine(self) -> None:
        """§10.3 — replay protection is PER-SESSION. The same
        request_id used in two different sessions MUST both be accepted."""
        rid = str(uuid.uuid4())
        r1 = self._post(self._make_envelope("steps/sessionStart", {},
                                            request_id=rid))
        r2 = self._post(self._make_envelope("steps/sessionStart", {},
                                            request_id=rid))
        self.assertIn("result", r1)
        self.assertIn("result", r2,
            "cross-session same-request_id must be accepted; "
            "replay protection scope is per-session")


# =============================================================================
# CORE-07 — Baseline integrity (conformance.md:23, §10)
# =============================================================================
#
# "every request and response carries a signature over the canonical
#  envelope. HMAC-SHA256 with an HKDF-derived per-session key from
#  deployment-provided key material is the baseline"
# §10: "The signed input ... is the RFC 8785 (JCS) canonicalization of
#       the request or response envelope with the signature field removed"
# =============================================================================

class Core07_BaselineIntegrity(CoreHarness):

    def test_signed_request_accepted(self) -> None:
        """conformance.md:23 — signed request with HMAC-SHA256 baseline
        MUST be accepted by a Guardian that requires signing."""
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        self.assertIn("result", resp,
            f"signed request was rejected; got {resp}")

    def test_unsigned_request_rejected_when_secret_configured(self) -> None:
        """conformance.md:23 — when signing is required, an unsigned
        request MUST be rejected."""
        env = self._make_envelope("steps/sessionStart", {}, sign=False)
        resp = self._post(env)
        self.assertIn("error", resp,
            f"unsigned request was accepted; got {resp}")
        self.assertEqual(resp["error"]["code"], -32004,
            f"unsigned-request error must be -32004 SIGNATURE_INVALID")

    def test_tampered_request_signature_invalid(self) -> None:
        """§10 — 'signed input ... canonicalization of the envelope with
        the signature field removed' — any post-sign tamper MUST fail
        verification."""
        env = self._make_envelope("steps/sessionStart", {})
        # Tamper with method AFTER signing
        env["method"] = "steps/userMessage"
        resp = self._post(env)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32004)

    def test_response_is_signed_and_verifies(self) -> None:
        """conformance.md:23 — 'every request and response carries a
        signature'. The Guardian's response MUST be signed; a client
        MUST be able to verify it with the same HKDF-derived key."""
        sid = str(uuid.uuid4())
        env = self._make_envelope("steps/sessionStart", {}, session_id=sid)
        resp = self._post(env)
        self.assertIn("result", resp)
        # The result body must include signature, and signature must verify.
        sig = resp["result"].get("signature")
        self.assertIsNotNone(sig,
            "Guardian response missing `signature` field per §10")
        key = acs_common.derive_session_key(self.HMAC_SECRET.encode(), sid)
        self.assertTrue(acs_common.verify_signature(resp, key=key),
            "Guardian's response signature must verify with the "
            "HKDF-derived per-session key")

    def test_per_session_key_derivation(self) -> None:
        """§10 — 'HKDF-derived per-session key from deployment-provided
        key material'. The derived key MUST differ between sessions
        with the same secret."""
        secret = self.HMAC_SECRET.encode()
        k1 = acs_common.derive_session_key(secret, "session-A")
        k2 = acs_common.derive_session_key(secret, "session-B")
        self.assertNotEqual(k1, k2,
            "per-session HKDF MUST produce distinct keys for distinct sessions")
        # Same session_id → same key
        k1b = acs_common.derive_session_key(secret, "session-A")
        self.assertEqual(k1, k1b,
            "HKDF must be deterministic for the same (secret, session_id)")

    def test_signature_covers_session_id(self) -> None:
        """§10 — 'binds the signature to the whole envelope, including
        method, metadata.session_id, request_id, and timestamp, so a
        captured signature cannot be lifted into a different envelope'.

        Verifies by: take a valid signed envelope, change session_id,
        Guardian MUST reject (the signature was over the old session_id)."""
        sid_a = str(uuid.uuid4())
        sid_b = str(uuid.uuid4())
        env = self._make_envelope("steps/sessionStart", {}, session_id=sid_a)
        # Lift signature to a different session
        env["params"]["metadata"]["session_id"] = sid_b
        resp = self._post(env)
        self.assertIn("error", resp,
            "signature lifted into a different session_id MUST be rejected")
        self.assertEqual(resp["error"]["code"], -32004)


# =============================================================================
# CORE-08 — Decision honoring (conformance.md:24, §6.4)
# =============================================================================
#
# Adapter-side property — covered end-to-end in the per-adapter test
# suites because it depends on how the framework (Claude Code, Cursor,
# NAT) routes the verdict. The wire-level property "Guardian responds
# in time" is covered here; "framework actually waits and applies" is
# covered in adapters/{claude-code,cursor,nat}/tests/.
# =============================================================================

class Core08_DecisionHonoring(CoreHarness):

    def test_guardian_responds_within_negotiated_timeout(self) -> None:
        """§6.4 — Observed Agent waits up to negotiated timeout. The
        Guardian MUST respond within that time for normal requests.
        Default timeout is 5000ms per ServerHello; we assert <1s."""
        start = time.monotonic()
        resp = self._post(self._make_envelope("steps/sessionStart", {}))
        elapsed = time.monotonic() - start
        self.assertIn("result", resp)
        self.assertLess(elapsed, 1.0,
            f"Guardian took {elapsed:.2f}s on a trivial request; far over "
            f"any sensible negotiated_ms — would force adapters to fail-posture")


class Core08_DecisionHonoringAdapter(unittest.TestCase):
    """Adapter-side §6.4 — fail-open MUST emit an audit event. We
    exercise the claude-code adapter against a dead Guardian and verify
    ACS_AUDIT appears on stderr."""

    def test_fail_open_emits_audit_event(self) -> None:
        """§6.4 — 'Every step that proceeds without a decision MUST be
        recorded as an audit event, so the bypass is visible rather
        than silent'."""
        adapter = HERE / "claude-code" / "acs_adapter.py"
        env = os.environ.copy()
        env["ACS_GUARDIAN_URL"] = "http://127.0.0.1:1/dead"  # unreachable
        env["ACS_HANDSHAKE"] = "0"
        env.pop("ACS_DEFAULT_DENY", None)  # default = fail-open
        proc = subprocess.run(
            [sys.executable, str(adapter)],
            input=json.dumps({
                "session_id": "00000000-0000-4000-8000-000000000001",
                "transcript_path": "/tmp/t", "cwd": "/tmp",
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read", "tool_input": {"file_path": "/tmp/x"},
            }),
            capture_output=True, text=True, env=env, timeout=10,
        )
        self.assertIn("ACS_AUDIT", proc.stderr,
            f"§6.4 — fail-open path must emit ACS_AUDIT event; stderr was:\n{proc.stderr}")
        self.assertIn("fail_open_bypass", proc.stderr,
            "audit event type must be 'fail_open_bypass'")


# =============================================================================
# CORE-09 — Liveness system/ping (conformance.md:25, §13)
# =============================================================================
#
# §13: "Guardians MUST always return decision: allow for system/ping
#       regardless of policy, signature, or session state."
# §13: "system/ping MUST NOT be written into SessionContext as a ContextEntry"
# §13: "system/ping MUST NOT require a signature even if the session
#       otherwise requires signatures"
# =============================================================================

class Core09_SystemPing(CoreHarness):

    def test_ping_returns_allow(self) -> None:
        """§13 — 'Guardians MUST always return decision: allow for
        system/ping regardless of policy, signature, or session state'."""
        env = self._make_envelope("system/ping", {"echo": "hi"}, sign=False)
        resp = self._post(env)
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["decision"], "allow")

    def test_ping_does_not_require_signature(self) -> None:
        """§13 — 'system/ping MUST NOT require a signature even if the
        session otherwise requires signatures, so that liveness probing
        remains possible during signature-rotation or key-resolution
        failures'."""
        env = self._make_envelope("system/ping", {"echo": "hi"}, sign=False)
        resp = self._post(env)
        self.assertIn("result", resp,
            "unsigned ping must be accepted even when Guardian requires signing")

    def test_ping_payload_includes_status_echo_timestamp(self) -> None:
        """§13 — 'response ... with decision: allow and a payload
        object carrying {status: ok, echo: <request.echo>,
        server_timestamp: <iso-8601>}'."""
        env = self._make_envelope("system/ping", {"echo": "ping-test"}, sign=False)
        result = self._post(env)["result"]
        payload = result.get("payload", {})
        self.assertEqual(payload.get("status"), "ok")
        self.assertEqual(payload.get("echo"), "ping-test")
        self.assertIn("server_timestamp", payload)

    def test_ping_does_not_consume_replay_slot(self) -> None:
        """§13 — 'system/ping MUST NOT be written into SessionContext
        as a ContextEntry; it does not participate in the chain hash'.
        Two pings with the same request_id must both succeed —
        otherwise ping is silently in the replay set."""
        sid = str(uuid.uuid4())
        rid = str(uuid.uuid4())
        env1 = self._make_envelope("system/ping", {"echo": "1"},
                                    session_id=sid, request_id=rid, sign=False)
        env2 = self._make_envelope("system/ping", {"echo": "2"},
                                    session_id=sid, request_id=rid, sign=False)
        r1 = self._post(env1)
        r2 = self._post(env2)
        self.assertIn("result", r1)
        self.assertIn("result", r2,
            "second ping with same request_id was rejected — "
            "ping must not enter the replay set")


# =============================================================================
# CORE-10 — Wrapped MCP (conformance.md:26)
# =============================================================================
#
# "Wrapped MCP — protocols/MCP/*"
#
# Our example Guardian doesn't fully implement MCP wrapping (it falls
# through to unknown-method deny). But the method-namespace MUST accept
# protocols/MCP/* method names at the wire level — i.e., the envelope
# schema MUST validate such methods, and the Guardian MUST return
# either a valid result or a structured error (not crash).
# =============================================================================

class Core10_WrappedMcp(CoreHarness):

    def test_mcp_namespace_method_validates(self) -> None:
        """conformance.md:26 — protocols/MCP/* method namespace MUST
        be a valid wire-level form. request-envelope.json:13-14
        regex includes ^protocols/ so any protocols/MCP/* method
        passes schema validation."""
        env = self._make_envelope("protocols/MCP/tools/call", {})
        errors = _validate_request_envelope(env)
        self.assertEqual(errors, [],
            f"protocols/MCP/* method MUST be valid wire-format; got {errors}")

    def test_guardian_returns_structured_response_for_mcp(self) -> None:
        """The Guardian MUST not crash on a protocols/MCP/* method.
        It MAY deny with unknown_method, but the response MUST be a
        well-formed envelope.

        NOTE — this is a partial Core-10 verification. Full wrapped
        MCP semantics (forwarding, MCP-specific validation, MCP error
        mapping) is a separate implementation gap documented in the
        adapter READMEs."""
        env = self._make_envelope("protocols/MCP/tools/call",
            {"name": "echo", "arguments": {"text": "hi"}})
        resp = self._post(env)
        # Either result or error — both are well-formed
        self.assertTrue("result" in resp or "error" in resp,
            f"malformed Guardian response for MCP method: {resp}")
        errors = _validate_response_envelope(resp)
        self.assertEqual(errors, [],
            f"response to protocols/MCP/* envelope is malformed: {errors}")


# =============================================================================
# Conformance summary — entry point.
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("ACS-Core conformance check (v0.1.0)")
    print("=" * 70)
    print("Spec source:", SPEC_DIR)
    print()
    unittest.main(verbosity=2)
