"""
Emission conformance — Claude Code adapter.

Proves the PRODUCTION adapter (acs_adapter.py, run as the real
subprocess Claude Code spawns) emits ACS-Core traffic that passes the
CANONICAL schemas. Unlike test_envelope_schema.py — which calls
build_request() directly — this captures the exact bytes the subprocess
sends over HTTP to a validating CaptureGuardian whose oracle is the
schema files (PR #22 emission review).

Every case asserts BOTH:
  - the expected ACS method was emitted exactly once, and
  - every captured envelope + payload passes its canonical schema and
    the protocol invariants (signature, UUIDs, RFC3339, metadata,
    argument wrapping).
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

SESSION = "11111111-1111-4111-8111-111111111111"


def _event(name: str, **extra) -> dict:
    base = {"session_id": SESSION, "transcript_path": "/tmp/t.jsonl",
            "cwd": "/tmp/work", "hook_event_name": name}
    base.update(extra)
    return base


class ClaudeEmission(unittest.TestCase):
    def _emit(self, event: dict) -> CaptureGuardian:
        """Run the real adapter subprocess against a CaptureGuardian and
        return the guardian holding the captured, validated traffic."""
        g = CaptureGuardian()
        with g, tempfile.TemporaryDirectory() as cache:
            env = os.environ.copy()
            env.update({
                "ACS_GUARDIAN_URL": g.url(),
                "ACS_HMAC_SECRET": g.hmac_secret,
                "ACS_HANDSHAKE": "1",           # capture the handshake too
                "ACS_HANDSHAKE_CACHE": cache,   # fresh → handshake fires
            })
            env.pop("ACS_HMAC_SECRET_FILE", None)
            proc = subprocess.run(
                [sys.executable, str(ADAPTER)],
                input=json.dumps(event),
                capture_output=True, text=True, env=env, timeout=20)
        self.assertEqual(proc.returncode, 0,
            f"adapter exited {proc.returncode}; stderr:\n{proc.stderr}")
        return g

    def _assert_emits(self, event: dict, method: str) -> CaptureGuardian:
        g = self._emit(event)
        # handshake is always first, then the event method — exactly once.
        self.assertEqual(g.records_for(method) and len(g.records_for(method)), 1,
            f"expected exactly one {method}; captured {g.methods()}")
        self.assertIn("handshake/hello", g.methods(),
            "adapter must handshake before the first content event")
        g.assert_all_valid(self)  # schema + invariants oracle
        return g

    # ----- Core matrix -----
    def test_session_start(self):
        self._assert_emits(_event("SessionStart", source="startup",
                                  model="claude-opus-4-7"), "steps/sessionStart")

    def test_user_message(self):
        self._assert_emits(_event("UserPromptSubmit", prompt="hi"),
                           "steps/userMessage")

    def test_tool_call_request(self):
        self._assert_emits(_event("PreToolUse", tool_name="Bash",
                                  tool_input={"command": "echo hi"},
                                  tool_use_id="t1", permission_mode="default"),
                           "steps/toolCallRequest")

    def test_tool_call_result(self):
        self._assert_emits(_event("PostToolUse", tool_name="Bash",
                                  tool_input={"command": "echo hi"},
                                  tool_response={"stdout": "hi", "interrupted": False},
                                  tool_use_id="t1", duration_ms=12), "steps/toolCallResult")

    def test_agent_response(self):
        self._assert_emits(_event("Notification", message="done",
                                  notification_type="permission_prompt"),
                           "steps/agentResponse")

    def test_session_end(self):
        self._assert_emits(_event("SessionEnd", reason="clear"),
                           "steps/sessionEnd")

    def test_stop_maps_to_session_end(self):
        # Stop is a distinct native event that also maps to sessionEnd;
        # covered here so emission owns every mapped native event's
        # schema validation (was a separate row in test_envelope_schema).
        self._assert_emits(_event("Stop", permission_mode="default"),
                           "steps/sessionEnd")

    def test_subagent_start_via_task(self):
        self._assert_emits(_event("PreToolUse", tool_name="Task",
                                  tool_input={"subagent_type": "researcher",
                                              "prompt": "look it up"},
                                  tool_use_id="task-1", permission_mode="default"),
                           "steps/subagentStart")

    def test_subagent_stop(self):
        self._assert_emits(_event("SubagentStop",
                                  transcript_path="/tmp/sub.jsonl",
                                  stop_hook_active=False), "steps/subagentStop")

    # (Handshake honesty is proved in ClaudeSequentialSession by
    #  comparing advertised methods to the set actually EMITTED across
    #  the full matrix — a real containment check, not "a schema for
    #  this method exists somewhere" — PR #22 emission re-review.)

    # ----- unmapped events must not masquerade as Core hooks -----
    def test_unknown_event_emits_nothing(self):
        g = self._emit(_event("SomeRenamedUpstreamHook"))
        # Only the (optional) handshake may appear; NO steps/* content hook.
        content = [m for m in g.methods() if m.startswith("steps/")]
        self.assertEqual(content, [],
            f"an unmapped event produced Core hook traffic: {content}")


class ClaudeSequentialSession(unittest.TestCase):
    """Session-level invariants need ONE Guardian + ONE handshake cache
    across an ordered sequence (a fresh Guardian per event can't prove
    them — PR #22 emission re-review). Proves: handshake fires exactly
    once, request_ids are unique, toolCallResult.request_id_ref links to
    its toolCallRequest, and the handshake advertises only methods the
    adapter DEMONSTRABLY emits in this run."""

    SEQUENCE = [
        _event("SessionStart", source="startup"),
        _event("UserPromptSubmit", prompt="do a thing"),
        _event("PreToolUse", tool_name="Bash", tool_input={"command": "echo hi"},
               tool_use_id="tc-1", permission_mode="default"),
        _event("PostToolUse", tool_name="Bash", tool_input={"command": "echo hi"},
               tool_response={"stdout": "hi", "interrupted": False},
               tool_use_id="tc-1", duration_ms=5),
        _event("Notification", message="fyi"),
        _event("PreToolUse", tool_name="Task",
               tool_input={"subagent_type": "researcher", "prompt": "x"},
               tool_use_id="task-1", permission_mode="default"),
        _event("SubagentStop", transcript_path="/tmp/sub.jsonl"),
        _event("SessionEnd", reason="clear"),
    ]

    @classmethod
    def setUpClass(cls):
        cls.g = CaptureGuardian()
        cls.g.start()
        cls._cache = tempfile.mkdtemp()
        for event in cls.SEQUENCE:
            env = os.environ.copy()
            env.update({
                "ACS_GUARDIAN_URL": cls.g.url(),
                "ACS_HMAC_SECRET": cls.g.hmac_secret,
                "ACS_HANDSHAKE": "1",
                "ACS_HANDSHAKE_CACHE": cls._cache,  # SHARED → handshake once
            })
            env.pop("ACS_HMAC_SECRET_FILE", None)
            subprocess.run([sys.executable, str(ADAPTER)],
                           input=json.dumps(event), capture_output=True,
                           text=True, env=env, timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.g.stop()

    def test_handshake_exactly_once(self):
        n = len(self.g.records_for("handshake/hello"))
        self.assertEqual(n, 1,
            f"handshake must fire once per session, not {n} times "
            f"(cache sharing broken?): {self.g.methods()}")

    def test_request_ids_unique(self):
        dupes = self.g.duplicate_request_ids()
        self.assertEqual(dupes, [],
            f"request_id MUST be unique per session; duplicates: {dupes}")

    def test_tool_result_references_its_request(self):
        req_id = self.g.request_id_for("steps/toolCallRequest")
        ref = self.g.payload_of("steps/toolCallResult").get("request_id_ref")
        self.assertIsNotNone(req_id)
        self.assertEqual(ref, req_id,
            "toolCallResult.request_id_ref must link back to the "
            f"toolCallRequest's request_id ({ref!r} != {req_id!r})")

    def test_handshake_advertises_only_demonstrably_emitted_methods(self):
        """The real honesty check: advertised methods_implemented ⊆ the
        set actually emitted in this session. A method advertised but
        never demonstrably emitted (e.g. steps/memoryStore) fails here —
        the earlier 'schema exists' check couldn't catch that."""
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
            f"handshake advertises methods this adapter never emitted in "
            f"the full matrix — advertised-but-unproven: {sorted(unproven)}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
