#!/usr/bin/env python3
"""
ACS adapter for Claude Code hooks.

Translates a Claude Code hook event (read from stdin as JSON) into an
ACS JSON-RPC request, sends it to a Guardian, and translates the ACS
response back into the format Claude Code expects (printed to stdout).

Schema source: https://code.claude.com/docs/en/hooks
ACS schema source: Agent-Control-Standard/ACS specification/v0.1.0/

Wire up via Claude Code's `~/.claude/settings.json`. See
settings.json.example in this directory.

Environment variables:
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    If "1", block on any adapter error or unknown
                      Guardian disposition. Default: "1".
  ACS_AGENT_ID        Explicit agent_id for metadata. If unset, derived
                      from cwd as `claude-code:<sha8(cwd)>`.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any


GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "1") == "1"
ACS_VERSION = "0.1.0"


# Claude Code hook_event_name -> ACS step method.
# Hooks where Claude Code does not expose all required payload fields
# (PreCompact has no entries_to_compact; PostCompact has no summary
# provenance or chain_hashes; SubagentStop has no final_chain_hash) are
# omitted: emitting a schema-non-conformant payload is worse than not
# emitting one.
HOOK_MAP: dict[str, str] = {
    "SessionStart": "steps/sessionStart",
    "SessionEnd": "steps/sessionEnd",
    "UserPromptSubmit": "steps/userMessage",
    "PreToolUse": "steps/toolCallRequest",
    "PostToolUse": "steps/toolCallResult",
    "Notification": "steps/agentResponse",
    "Stop": "steps/sessionEnd",
}


# Claude Code SessionEnd reasons -> spec session-end.json reason enum
# (completed/cancelled/error/timeout/abandoned)
SESSION_END_REASON_MAP: dict[str, str] = {
    "clear": "completed",
    "logout": "abandoned",
    "prompt_input_exit": "abandoned",
    "other": "completed",
}


def _iso8601_now() -> str:
    """RFC3339 / ISO-8601 timestamp with millisecond precision and Z suffix."""
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _agent_id(event: dict[str, Any]) -> str:
    explicit = os.environ.get("ACS_AGENT_ID")
    if explicit:
        return explicit
    cwd = event.get("cwd") or os.environ.get("PWD") or ""
    if cwd:
        return f"claude-code:{hashlib.sha256(cwd.encode()).hexdigest()[:8]}"
    return "claude-code:unknown"


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    """tool-call-request.json:26-37 — each arg is {value, provenance?}."""
    return {k: {"value": v} for k, v in (raw or {}).items()}


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Build the hook-specific payload — goes inside params.payload.

    Each branch returns a payload that validates against the corresponding
    `specification/v0.1.0/hooks/<hook>.json` schema.
    """
    name = event.get("hook_event_name", "")

    if name == "PreToolUse":
        # tool-call-request.json: required [tool, arguments]
        return {
            "tool": {"name": event.get("tool_name", "")},
            "arguments": _wrap_arguments(event.get("tool_input") or {}),
        }

    if name == "PostToolUse":
        # tool-call-result.json: required [tool, exit_status, outputs]
        # exit_status enum: success/failure/timeout/blocked
        tool_response = event.get("tool_response", event.get("tool_output"))
        if isinstance(tool_response, dict) and tool_response.get("interrupted"):
            exit_status = "failure"
        else:
            exit_status = "success"
        payload: dict[str, Any] = {
            "tool": {"name": event.get("tool_name", "")},
            "exit_status": exit_status,
            "outputs": [{"value": tool_response}] if tool_response is not None else [],
        }
        if event.get("duration_ms") is not None:
            payload["duration_ms"] = event["duration_ms"]
        return payload

    if name == "UserPromptSubmit":
        # user-message.json: required [content]; content is array of {type, value, provenance?}
        return {
            "content": [{"type": "text", "value": event.get("prompt", "")}],
        }

    if name == "Notification":
        # agent-response.json: required [content]; content is array of {type, value, provenance?}
        return {
            "content": [{"type": "text", "value": event.get("message", "")}],
        }

    if name == "SessionStart":
        # session-start.json: all fields optional
        out: dict[str, Any] = {}
        if event.get("source") or event.get("model"):
            out["platform_context"] = {
                k: v for k, v in (("source", event.get("source")),
                                  ("model", event.get("model")),
                                  ("transcript_path", event.get("transcript_path"))) if v
            }
        return out

    if name in ("SessionEnd", "Stop"):
        # session-end.json: required [reason], reason enum
        raw_reason = event.get("reason") or ("completed" if name == "Stop" else "other")
        return {"reason": SESSION_END_REASON_MAP.get(raw_reason, "completed")}

    return {}


def build_request(event: dict[str, Any]) -> dict[str, Any]:
    """Build an ACS request envelope conforming to request-envelope.json.

    Top-level keys (additionalProperties: false): jsonrpc, method, id, params.
    params (required): acs_version, request_id, timestamp, metadata, payload.
    metadata (required): agent_id, session_id.
    """
    method = HOOK_MAP.get(event.get("hook_event_name", ""))
    if method is None:
        return {}

    session_id = event.get("session_id")
    if not session_id:
        # request-envelope.json:62 makes session_id required and UUID-formatted.
        # Without it we cannot construct a valid envelope.
        return {}

    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": session_id,
    }
    # Optional context fields (additionalProperties is allowed on metadata)
    if event.get("cwd"):
        metadata["cwd"] = event["cwd"]
    if event.get("transcript_path"):
        metadata["transcript_path"] = event["transcript_path"]
    if event.get("permission_mode"):
        metadata["permission_mode"] = event["permission_mode"]
    metadata["platform"] = "claude-code"

    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": _iso8601_now(),
            "metadata": metadata,
            "payload": build_payload(event),
        },
    }


def call_guardian(request: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(request).encode("utf-8")
    req = urllib.request.Request(
        GUARDIAN_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ACS disposition -> Claude Code permissionDecision (PreToolUse only)
PRETOOL_PERMISSION_MAP: dict[str, str] = {
    "allow": "allow",
    "deny": "deny",
    "ask": "ask",
    "defer": "defer",
}

KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


def translate_response(acs_response: dict[str, Any], hook_event: str) -> dict[str, Any]:
    """Translate an ACS decision envelope to Claude Code's expected output.

    Schema reference: https://code.claude.com/docs/en/hooks

    Unknown / missing decisions respect ACS_DEFAULT_DENY: on True, the
    adapter emits a deny in the hook's native shape rather than silently
    proceeding.
    """
    result = acs_response.get("result", {})
    decision = (result.get("decision") or "").lower()
    reasoning = result.get("reasoning", "")
    modifications = result.get("modifications", {})

    # Default-deny on unknown / empty disposition. Done up front so every
    # hook branch can assume a known decision (or fall through to the
    # informational branch).
    if decision not in KNOWN_DECISIONS and DEFAULT_DENY:
        deny_reason = f"unknown Guardian disposition '{decision}' (default-deny)"
        if hook_event == "PreToolUse":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": deny_reason,
                }
            }
        if hook_event in ("PostToolUse", "UserPromptSubmit", "Stop", "SubagentStop", "PreCompact"):
            return {"decision": "block", "reason": deny_reason}
        # Informational hooks have no gating contract; degrade to allow.

    # ----- PreToolUse: permissionDecision under hookSpecificOutput -----
    if hook_event == "PreToolUse":
        hso: dict[str, Any] = {"hookEventName": "PreToolUse"}
        if decision in PRETOOL_PERMISSION_MAP:
            hso["permissionDecision"] = PRETOOL_PERMISSION_MAP[decision]
            if reasoning:
                hso["permissionDecisionReason"] = reasoning
            return {"hookSpecificOutput": hso}
        if decision == "modify":
            overrides = modifications.get("parameter_overrides")
            if overrides is not None:
                hso["permissionDecision"] = "allow"
                hso["updatedInput"] = overrides
                if reasoning:
                    hso["permissionDecisionReason"] = reasoning
                return {"hookSpecificOutput": hso}
            hso["permissionDecision"] = "deny"
            hso["permissionDecisionReason"] = (
                f"MODIFY substituted to DENY (no parameter_overrides): {reasoning}"
            )
            return {"hookSpecificOutput": hso}
        return {}

    # ----- PostToolUse -----
    if hook_event == "PostToolUse":
        if decision == "deny":
            return {
                "decision": "block",
                "reason": reasoning or "blocked by Guardian",
                "hookSpecificOutput": {"hookEventName": "PostToolUse"},
            }
        if decision == "modify":
            updated = modifications.get("modified_content")
            if updated is not None:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "updatedToolOutput": str(updated),
                        **({"additionalContext": reasoning} if reasoning else {}),
                    }
                }
            return {
                "decision": "block",
                "reason": f"MODIFY substituted to DENY (no modified_content): {reasoning}",
            }
        if decision in ("ask", "defer"):
            return {
                "decision": "block",
                "reason": f"{decision} on post-tool not supported by Claude Code: {reasoning}",
            }
        return {}

    # ----- UserPromptSubmit -----
    if hook_event == "UserPromptSubmit":
        if decision == "deny":
            return {"decision": "block", "reason": reasoning or "blocked by Guardian"}
        if decision in ("ask", "defer"):
            return {"decision": "block", "reason": f"{decision} on user prompt: {reasoning}"}
        return {}

    if hook_event in ("Stop", "SubagentStop"):
        if decision == "deny":
            return {"decision": "block", "reason": reasoning or "blocked by Guardian"}
        return {}

    if hook_event == "PreCompact":
        if decision == "deny":
            return {
                "decision": "block",
                "reason": reasoning or "compaction blocked by Guardian",
                "hookSpecificOutput": {"hookEventName": "PreCompact"},
            }
        return {}

    # ----- Informational hooks -----
    additional = result.get("additional_context")
    if additional:
        return {
            "hookSpecificOutput": {
                "hookEventName": hook_event,
                "additionalContext": str(additional),
            }
        }
    return {}


def main() -> int:
    raw = sys.stdin.read().strip()
    if not raw:
        return 0
    try:
        event = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"acs-adapter: invalid JSON on stdin: {e}\n")
        return _fail()

    hook_name = event.get("hook_event_name", "")
    if hook_name not in HOOK_MAP:
        return 0

    try:
        request = build_request(event)
        if not request:
            sys.stderr.write(f"acs-adapter: could not build request for {hook_name}\n")
            return _fail(hook_name)
        response = call_guardian(request)
        out = translate_response(response, hook_name)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return _fail(hook_name)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(hook_name)

    if out:
        json.dump(out, sys.stdout)
        sys.stdout.write("\n")
    return 0


def _fail(hook_name: str = "") -> int:
    """Emit a fail-closed response in the shape the hook expects."""
    if not DEFAULT_DENY:
        return 0
    msg = "ACS adapter: Guardian unreachable"
    if hook_name == "PreToolUse":
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": msg,
                }
            },
            sys.stdout,
        )
    elif hook_name in ("PostToolUse", "UserPromptSubmit", "Stop", "SubagentStop", "PreCompact"):
        json.dump({"decision": "block", "reason": msg}, sys.stdout)
    else:
        return 0
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
