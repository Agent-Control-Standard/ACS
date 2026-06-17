"""
Spec-validation tests for the Claude Code adapter.

Ground truth: the canonical v0.1.0 schemas at
`specification/v0.1.0/request-envelope.json` and
`specification/v0.1.0/hooks/*.json` in the upstream
Agent-Control-Standard/ACS repo.

NOT validated against the example Guardian. These tests fail the
moment the adapter's wire format drifts from the spec, independent
of whether the round-trip tests pass.

Spec source defaults to /tmp/acs-spec-source/specification/v0.1.0;
override with ACS_SPEC_DIR.
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
    validator = Draft202012Validator(schema, resolver=resolver)
    return [
        f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(payload)
    ]


def _event(name: str, **extra) -> dict:
    """Build a Claude Code-shaped hook event."""
    base = {
        "session_id": "00000000-0000-0000-0000-000000000001",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp/work",
        "hook_event_name": name,
    }
    base.update(extra)
    return base


# (event_name, payload_schema_name, fixture builder)
HOOK_CASES = [
    ("PreToolUse", "hooks/tool-call-request.json", lambda: _event(
        "PreToolUse", tool_name="Bash", tool_input={"command": "echo hi"},
        tool_use_id="t1", permission_mode="default",
    )),
    ("PostToolUse", "hooks/tool-call-result.json", lambda: _event(
        "PostToolUse", tool_name="Bash", tool_input={"command": "echo hi"},
        tool_response={"stdout": "hi", "stderr": "", "interrupted": False,
                       "isImage": False, "noOutputExpected": False},
        tool_use_id="t1", duration_ms=12, permission_mode="default",
    )),
    ("UserPromptSubmit", "hooks/user-message.json", lambda: _event(
        "UserPromptSubmit", prompt="summarize my emails",
    )),
    ("SessionStart", "hooks/session-start.json", lambda: _event(
        "SessionStart", source="startup", model="claude-opus-4-7",
    )),
    ("SessionEnd", "hooks/session-end.json", lambda: _event(
        "SessionEnd", reason="clear",
    )),
    ("Notification", "hooks/agent-response.json", lambda: _event(
        "Notification", message="confirm action", notification_type="permission_prompt",
    )),
    ("Stop", "hooks/session-end.json", lambda: _event(
        "Stop", permission_mode="default",
    )),
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
    """Every adapter-emitted envelope MUST validate against request-envelope.json."""


def _make_envelope_test(event_name, _schema, fixture):
    def test(self):
        envelope = acs_adapter.build_request(fixture())
        errors = _validate(envelope, "request-envelope.json")
        self.assertEqual(errors, [],
                         f"{event_name} envelope FAILS request-envelope.json:\n  - "
                         + "\n  - ".join(errors))
    test.__name__ = f"test_envelope_{event_name}"
    return test


class PayloadMatchesHookSchema(SpecValidationSetUp):
    """params.payload MUST validate against the per-hook schema."""


def _make_payload_test(event_name, schema_name, fixture):
    def test(self):
        envelope = acs_adapter.build_request(fixture())
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


# Attach generated tests so every mapped hook is covered, not just toolCallRequest.
for _event_name, _schema, _fixture in HOOK_CASES:
    setattr(EnvelopeMatchesV010Schema, f"test_envelope_{_event_name}",
            _make_envelope_test(_event_name, _schema, _fixture))
    setattr(PayloadMatchesHookSchema, f"test_payload_{_event_name}",
            _make_payload_test(_event_name, _schema, _fixture))


class TimestampIsISO8601(SpecValidationSetUp):
    def test_timestamp_is_iso8601_string(self) -> None:
        """request-envelope.json:38-40 — timestamp is string format date-time."""
        envelope = acs_adapter.build_request(_event(
            "PreToolUse", tool_name="Read", tool_input={"file_path": "/x"},
        ))
        ts = envelope["params"]["timestamp"]
        self.assertIsInstance(ts, str)
        import datetime as _dt
        # Round-trippable as ISO 8601; trailing Z handled
        _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))


class MetadataRequiredFields(SpecValidationSetUp):
    def test_metadata_has_agent_and_session(self) -> None:
        """request-envelope.json:62 — metadata.required = [agent_id, session_id]."""
        envelope = acs_adapter.build_request(_event(
            "PreToolUse", tool_name="Read", tool_input={"file_path": "/x"},
        ))
        meta = envelope["params"]["metadata"]
        self.assertIn("agent_id", meta)
        self.assertIn("session_id", meta)
        self.assertTrue(meta["agent_id"])
        self.assertTrue(meta["session_id"])


class ArgumentsAreWrapped(SpecValidationSetUp):
    def test_pretool_arguments_each_have_value_key(self) -> None:
        """tool-call-request.json:26-37 — each argument is {value, provenance?}."""
        envelope = acs_adapter.build_request(_event(
            "PreToolUse", tool_name="Bash", tool_input={"command": "ls", "timeout": 60},
        ))
        args = envelope["params"]["payload"]["arguments"]
        self.assertEqual(set(args.keys()), {"command", "timeout"})
        for k, v in args.items():
            self.assertIn("value", v, f"argument '{k}' missing 'value' wrapper: {v}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
