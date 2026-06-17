"""
Spec-validation tests for the Cursor adapter.

Validates every adapter-emitted envelope against the canonical v0.1.0
`request-envelope.json`, and every per-hook payload against its
corresponding `hooks/<hook>.json` schema. Fails the moment the
adapter's wire format drifts from the spec.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.validators import RefResolver


SPEC_DIR_DEFAULT = Path("/tmp/acs-spec-source/specification/v0.1.0")
SPEC_DIR = Path(os.environ.get("ACS_SPEC_DIR", str(SPEC_DIR_DEFAULT)))

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
sys.path.insert(0, str(ADAPTER_DIR))

import acs_adapter  # noqa: E402


def _load_schema(name: str) -> dict:
    with open(SPEC_DIR / name) as f:
        return json.load(f)


def _validate(payload: dict, schema_name: str) -> list:
    schema = _load_schema(schema_name)
    resolver = RefResolver(
        base_uri=(SPEC_DIR.as_uri() + "/" + schema_name),
        referrer=schema,
    )
    validator = Draft202012Validator(
        schema, resolver=resolver,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    return [
        f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(payload)
    ]


SESSION_UUID = "00000000-0000-0000-0000-000000000001"

# (event_name, payload schema, fixture builder)
HOOK_CASES = [
    ("preToolUse", "hooks/tool-call-request.json", {
        "session_id": SESSION_UUID,
        "workspace_path": "/tmp/workspace",
        "tool_name": "edit_file",
        "tool_input": {"file_path": "/tmp/x.py", "patch": "..."},
    }),
    ("postToolUse", "hooks/tool-call-result.json", {
        "session_id": SESSION_UUID,
        "workspace_path": "/tmp/workspace",
        "tool_name": "edit_file",
        "tool_input": {"file_path": "/tmp/x.py"},
        "tool_output": "patched 1 file",
    }),
    ("postToolUseFailure", "hooks/tool-call-result.json", {
        "session_id": SESSION_UUID,
        "tool_name": "edit_file",
        "tool_input": {"file_path": "/tmp/x.py"},
        "tool_output": "error: file not found",
    }),
    ("beforeShellExecution", "hooks/tool-call-request.json", {
        "session_id": SESSION_UUID,
        "command": "ls -la",
    }),
    ("afterShellExecution", "hooks/tool-call-result.json", {
        "session_id": SESSION_UUID,
        "command": "ls -la",
        "output": "total 0",
        "exit_code": 0,
    }),
    ("beforeMCPExecution", "hooks/tool-call-request.json", {
        "session_id": SESSION_UUID,
        "mcp_server": "linear",
        "mcp_tool": "list_issues",
        "tool_input": {"team": "ACS"},
    }),
    ("afterMCPExecution", "hooks/tool-call-result.json", {
        "session_id": SESSION_UUID,
        "mcp_server": "linear",
        "mcp_tool": "list_issues",
        "tool_output": [{"id": "ACS-1"}],
    }),
    ("afterFileEdit", "hooks/tool-call-result.json", {
        "session_id": SESSION_UUID,
        "file_path": "/tmp/x.py",
    }),
    ("afterTabFileEdit", "hooks/tool-call-result.json", {
        "session_id": SESSION_UUID,
        "file_path": "/tmp/x.py",
    }),
    ("beforeSubmitPrompt", "hooks/user-message.json", {
        "session_id": SESSION_UUID,
        "prompt": "list open PRs",
    }),
    ("afterAgentResponse", "hooks/agent-response.json", {
        "session_id": SESSION_UUID,
        "response": "done",
    }),
    ("afterAgentThought", "hooks/agent-response.json", {
        "session_id": SESSION_UUID,
        "thought": "thinking about it",
    }),
    ("sessionStart", "hooks/session-start.json", {
        "session_id": SESSION_UUID,
        "workspace_path": "/tmp/workspace",
    }),
    ("sessionEnd", "hooks/session-end.json", {
        "session_id": SESSION_UUID,
        "reason": "completed",
    }),
    ("stop", "hooks/session-end.json", {
        "session_id": SESSION_UUID,
    }),
    ("subagentStart", "hooks/subagent-start.json", {
        "session_id": SESSION_UUID,
        "subagent_id": "sub-1",
        "subagent_type": "researcher",
    }),
    # subagentStop intentionally NOT in HOOK_MAP — `final_chain_hash` is
    # genuinely unknowable from Cursor (no chain on its side). Documented
    # in the Cursor README per-hook honesty table.
    ("preCompact", "hooks/pre-compact.json", {
        "session_id": SESSION_UUID,
        "trigger": "size_threshold",
    }),
]


class SpecValidationSetUp(unittest.TestCase):
    def setUp(self) -> None:
        if not SPEC_DIR.exists():
            self.fail(
                f"Canonical spec schemas not found at {SPEC_DIR}. "
                "Clone Agent-Control-Standard/ACS and set ACS_SPEC_DIR. "
                "Spec validation is non-negotiable; this is not a skip."
            )


class EnvelopeMatchesV010Schema(SpecValidationSetUp):
    pass


def _make_envelope_test(event_name, _schema, fixture):
    def test(self):
        envelope = acs_adapter.build_request(event_name, fixture)
        errors = _validate(envelope, "request-envelope.json")
        self.assertEqual(errors, [],
                         f"{event_name} envelope FAILS request-envelope.json:\n  - "
                         + "\n  - ".join(errors))
    test.__name__ = f"test_envelope_{event_name}"
    return test


class PayloadMatchesHookSchema(SpecValidationSetUp):
    pass


def _make_payload_test(event_name, schema_name, fixture):
    def test(self):
        envelope = acs_adapter.build_request(event_name, fixture)
        payload = envelope.get("params", {}).get("payload")
        self.assertIsNotNone(
            payload,
            f"{event_name}: envelope missing params.payload "
            f"(got params keys: {list(envelope.get('params', {}).keys())})",
        )
        errors = _validate(payload, schema_name)
        self.assertEqual(errors, [],
                         f"{event_name} payload FAILS {schema_name}:\n  - "
                         + "\n  - ".join(errors))
    test.__name__ = f"test_payload_{event_name}"
    return test


for _event_name, _schema, _fixture in HOOK_CASES:
    setattr(EnvelopeMatchesV010Schema, f"test_envelope_{_event_name}",
            _make_envelope_test(_event_name, _schema, _fixture))
    setattr(PayloadMatchesHookSchema, f"test_payload_{_event_name}",
            _make_payload_test(_event_name, _schema, _fixture))


class UuidCoercionForNonUuidCursorIds(SpecValidationSetUp):
    """Cursor's real conversation_id is not always a UUID — `conv-abc123`,
    `chat_xyz`, etc. The adapter MUST coerce it to a valid UUID via uuid5
    before emitting (request-envelope.json:66 requires `metadata.session_id`
    to be `format: "uuid"`). Without coercion, format-checker validation
    fails. These fixtures exercise that path — the canonical-UUID fixtures
    in HOOK_CASES would pass through unchanged and miss the coercion bug.
    """

    NON_UUID_INPUTS = [
        "conv-abc123def456",            # Cursor-style conversation id
        "chat_2026_session_xyz",        # underscore-style
        "test-cc-session",              # the string the round-trip tests use
        "",                             # empty — adapter should refuse, see below
    ]

    def test_non_uuid_conversation_id_coerced(self) -> None:
        """A non-UUID conversation_id MUST come out as a valid UUID in
        metadata.session_id — otherwise envelope validation fails."""
        import re
        UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                             r"[0-9a-f]{4}-[0-9a-f]{12}$")
        for non_uuid in self.NON_UUID_INPUTS:
            if not non_uuid:
                # Empty session_id: adapter refuses to build the envelope at all.
                env = acs_adapter.build_request("preToolUse",
                    {"session_id": non_uuid, "tool_name": "Read",
                     "tool_input": {"file_path": "/tmp/x"}})
                self.assertEqual(env, {},
                    f"adapter must refuse to build envelope for empty session_id; got {env}")
                continue

            env = acs_adapter.build_request("preToolUse",
                {"session_id": non_uuid, "tool_name": "Read",
                 "tool_input": {"file_path": "/tmp/x"}})
            session_id = env["params"]["metadata"]["session_id"]
            self.assertTrue(UUID_RE.match(session_id),
                f"adapter emitted non-UUID session_id {session_id!r} "
                f"for input {non_uuid!r}; format-checker would reject")
            # Also: the canonical schema (with format_checker) must accept it
            errors = _validate(env, "request-envelope.json")
            self.assertEqual(errors, [],
                f"envelope for non-UUID input {non_uuid!r} fails canonical schema:\n  - "
                + "\n  - ".join(errors))

    def test_uuid_coercion_is_deterministic(self) -> None:
        """The same non-UUID input MUST always coerce to the same UUID,
        so subagentStart and a later subagentStop can both reference the
        same subagent across hooks."""
        env1 = acs_adapter.build_request("preToolUse",
            {"session_id": "conv-stable-id", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}})
        env2 = acs_adapter.build_request("preToolUse",
            {"session_id": "conv-stable-id", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/y"}})
        self.assertEqual(env1["params"]["metadata"]["session_id"],
                         env2["params"]["metadata"]["session_id"],
                         "uuid5 coercion must be deterministic — different "
                         "UUIDs for the same input means cross-hook correlation "
                         "is broken")


if __name__ == "__main__":
    unittest.main(verbosity=2)
