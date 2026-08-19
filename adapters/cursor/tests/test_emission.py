"""
Emission conformance — Cursor adapter.

Same contract as the Claude Code emission suite: run the PRODUCTION
adapter as the real subprocess Cursor spawns (`acs_adapter.py <event>`),
capture the exact bytes against a validating CaptureGuardian whose
oracle is the canonical schemas, and assert method-emitted-once +
schema-valid + protocol invariants (PR #22 emission review).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent / "acs_adapter.py"
COMMON = HERE.parent.parent / "_common"
sys.path.insert(0, str(COMMON))

from capture_guardian import CaptureGuardian  # noqa: E402

# Realistic Cursor conversation id — NOT a UUID. Forces the production
# emission path through _coerce_uuid so the captured metadata.session_id
# (which CaptureGuardian requires to be a UUID) proves coercion actually
# happens on the wire, not just in the direct transform unit tests
# (PR #22 emission re-review).
SESSION = "conv-cursor-emission-01"


class CursorEmission(unittest.TestCase):
    def _emit(self, event_name: str, event: dict) -> CaptureGuardian:
        g = CaptureGuardian()
        event = {"session_id": SESSION, "workspace_path": "/tmp/work", **event}
        with g, tempfile.TemporaryDirectory() as cache:
            env = os.environ.copy()
            env.update({
                "ACS_GUARDIAN_URL": g.url(),
                "ACS_HMAC_SECRET": g.hmac_secret,
                "ACS_HANDSHAKE": "1",
                "ACS_HANDSHAKE_CACHE": cache,
                # subagentStart needs a recorded prior step OR falls back
                # to the spawn's own request_id — either way it's honest;
                # isolate session state so runs don't interfere.
                "ACS_SESSION_STATE_DIR": cache,
            })
            env.pop("ACS_HMAC_SECRET_FILE", None)
            proc = subprocess.run(
                [sys.executable, str(ADAPTER), event_name],
                input=json.dumps(event),
                capture_output=True, text=True, env=env, timeout=20)
        self.assertIn(proc.returncode, (0, 2),
            f"adapter exited {proc.returncode}; stderr:\n{proc.stderr}")
        return g

    def _assert_emits(self, event_name: str, event: dict, method: str):
        g = self._emit(event_name, event)
        self.assertEqual(len(g.records_for(method)), 1,
            f"expected exactly one {method}; captured {g.methods()}")
        self.assertIn("handshake/hello", g.methods())
        g.assert_all_valid(self)
        return g

    def test_session_start(self):
        self._assert_emits("sessionStart", {}, "steps/sessionStart")

    def test_user_message(self):
        self._assert_emits("beforeSubmitPrompt", {"prompt": "hi"},
                           "steps/userMessage")

    def test_tool_call_request(self):
        self._assert_emits("preToolUse",
                           {"tool_name": "Bash", "tool_input": {"command": "echo hi"},
                            "tool_call_id": "c1"}, "steps/toolCallRequest")

    def test_tool_call_result(self):
        self._assert_emits("postToolUse",
                           {"tool_name": "Bash", "tool_output": "hi",
                            "tool_call_id": "c1"}, "steps/toolCallResult")

    def test_agent_response(self):
        self._assert_emits("afterAgentResponse", {"response": "done"},
                           "steps/agentResponse")

    def test_session_end(self):
        self._assert_emits("sessionEnd", {"reason": "completed"},
                           "steps/sessionEnd")

    def test_subagent_start(self):
        self._assert_emits("subagentStart",
                           {"subagent_id": "sub-1", "subagent_type": "explore"},
                           "steps/subagentStart")

    # Remaining mapped native events — moved here from the deleted
    # test_envelope_schema.py so the production-emission layer (stronger:
    # real subprocess bytes vs. build_request output) is the SOLE schema
    # owner. Each proves its native-event → ACS-method flattening yields
    # a schema-valid, signed envelope (PR #22 emission re-review, dedup).
    EXTRA_NATIVE = [
        ("postToolUseFailure", {"tool_name": "edit_file",
            "tool_input": {"file_path": "/tmp/x.py"},
            "tool_output": "error: not found"}, "steps/toolCallResult"),
        ("beforeShellExecution", {"command": "ls -la"}, "steps/toolCallRequest"),
        ("afterShellExecution", {"command": "ls -la", "output": "total 0",
            "exit_code": 0}, "steps/toolCallResult"),
        ("beforeMCPExecution", {"mcp_server": "linear", "mcp_tool": "list_issues",
            "tool_input": {"team": "ACS"}}, "steps/toolCallRequest"),
        ("afterMCPExecution", {"mcp_server": "linear", "mcp_tool": "list_issues",
            "tool_output": [{"id": "ACS-1"}]}, "steps/toolCallResult"),
        ("afterFileEdit", {"file_path": "/tmp/x.py"}, "steps/toolCallResult"),
        ("afterTabFileEdit", {"file_path": "/tmp/x.py"}, "steps/toolCallResult"),
        ("afterAgentThought", {"thought": "thinking"}, "steps/agentResponse"),
        ("stop", {}, "steps/sessionEnd"),
    ]

    def test_extra_native_events_emit_valid(self):
        for event_name, body, method in self.EXTRA_NATIVE:
            with self.subTest(event=event_name):
                self._assert_emits(event_name, body, method)

    # (Handshake honesty is proved in CursorSequentialSession against the
    #  set actually EMITTED across the matrix — PR #22 emission re-review.)

    def test_unknown_event_emits_no_core_hook(self):
        g = self._emit("someRenamedUpstreamHook", {})
        content = [m for m in g.methods() if m.startswith("steps/")]
        self.assertEqual(content, [],
            f"an unmapped event produced Core hook traffic: {content}")

    def test_non_uuid_session_coerced_on_the_wire(self):
        """SESSION is a realistic non-UUID Cursor id; the captured
        envelope's metadata.session_id MUST be a coerced UUID (not the
        raw string) — proving coercion on the PRODUCTION path, not just
        in the direct transform unit tests."""
        import uuid
        g = self._emit("preToolUse", {"tool_name": "Read",
                                      "tool_input": {"file_path": "/tmp/x"}})
        wire_sid = (g.only("steps/toolCallRequest").parsed["params"]
                    ["metadata"]["session_id"])
        self.assertNotEqual(wire_sid, SESSION,
            "raw non-UUID session id leaked onto the wire uncoerced")
        uuid.UUID(wire_sid)  # raises if not a valid UUID
        g.assert_all_valid(self)


class CursorSequentialSession(unittest.TestCase):
    """One Guardian + one handshake cache + one session-state dir across
    an ordered sequence. Proves handshake-once, unique request_ids,
    request_id_ref linkage, and advertised ⊆ emitted. The shared session
    state also lets preCompact emit a VALID entries_to_compact (it needs
    a prior recorded step) — so preCompact, which the handshake
    advertises, is actually demonstrated (PR #22 emission re-review)."""

    # (event_name, event_body) in order
    SEQUENCE = [
        ("sessionStart", {}),
        ("beforeSubmitPrompt", {"prompt": "do a thing"}),
        ("preToolUse", {"tool_name": "Bash", "tool_input": {"command": "echo hi"},
                        "tool_call_id": "c1"}),
        ("postToolUse", {"tool_name": "Bash", "tool_output": "hi",
                         "tool_call_id": "c1"}),
        ("afterAgentResponse", {"response": "done"}),
        ("preCompact", {"trigger": "size_threshold"}),
        ("subagentStart", {"subagent_id": "sub-1", "subagent_type": "explore"}),
        ("sessionEnd", {"reason": "completed"}),
    ]
    SESSION = "conv-cursor-sequential-01"  # non-UUID: exercises coercion across the stateful sequence too

    @classmethod
    def setUpClass(cls):
        cls.g = CaptureGuardian()
        cls.g.start()
        cls._cache = tempfile.mkdtemp()
        for name, body in cls.SEQUENCE:
            event = {"session_id": cls.SESSION, "workspace_path": "/tmp/work", **body}
            env = os.environ.copy()
            env.update({
                "ACS_GUARDIAN_URL": cls.g.url(),
                "ACS_HMAC_SECRET": cls.g.hmac_secret,
                "ACS_HANDSHAKE": "1",
                "ACS_HANDSHAKE_CACHE": cls._cache,      # SHARED → handshake once
                "ACS_SESSION_STATE_DIR": cls._cache,    # SHARED → preCompact entries populate
            })
            env.pop("ACS_HMAC_SECRET_FILE", None)
            subprocess.run([sys.executable, str(ADAPTER), name],
                           input=json.dumps(event), capture_output=True,
                           text=True, env=env, timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.g.stop()

    def test_all_captures_valid(self):
        self.g.assert_all_valid(self)

    def test_precompact_emitted_with_valid_entries(self):
        recs = self.g.records_for("steps/preCompact")
        self.assertEqual(len(recs), 1,
            f"preCompact should have emitted once; got {self.g.methods()}")
        entries = (recs[0].parsed.get("params") or {}).get("payload", {}).get("entries_to_compact")
        self.assertTrue(entries,
            "preCompact entries_to_compact must be non-empty (shared session "
            "state should carry the prior step_ids)")

    def test_handshake_exactly_once(self):
        self.assertEqual(len(self.g.records_for("handshake/hello")), 1,
            f"handshake must fire once per session: {self.g.methods()}")

    def test_request_ids_unique(self):
        self.assertEqual(self.g.duplicate_request_ids(), [],
            "request_id MUST be unique per session")

    def test_tool_result_references_its_request(self):
        req_id = self.g.request_id_for("steps/toolCallRequest")
        ref = self.g.payload_of("steps/toolCallResult").get("request_id_ref")
        self.assertIsNotNone(req_id)
        self.assertEqual(ref, req_id,
            f"toolCallResult.request_id_ref must link to its request "
            f"({ref!r} != {req_id!r})")

    def test_handshake_advertises_only_demonstrably_emitted_methods(self):
        advertised = set(self.g.handshake_methods_implemented())
        emitted = {m for m in self.g.methods() if m != "handshake/hello"}
        # BOTH directions: advertised == emitted. subset alone missed
        # under-advertising — emitting an undeclared method stayed green
        # (PR #22 emission re-review).
        self.assertEqual(advertised, emitted,
            f"advertised != emitted; over-advertised={sorted(advertised - emitted)}, "
            f"under-advertised={sorted(emitted - advertised)}")
        unproven = advertised - emitted
        self.assertEqual(unproven, set(),
            f"handshake advertises methods never emitted in the matrix: "
            f"{sorted(unproven)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
