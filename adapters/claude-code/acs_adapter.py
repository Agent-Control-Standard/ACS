#!/usr/bin/env python3
"""
ACS adapter for Claude Code hooks.

Translates a Claude Code hook event (read from stdin as JSON) into an
ACS JSON-RPC request, sends it to a Guardian, and translates the ACS
response back into the format Claude Code expects (printed to stdout).

Schema source: https://code.claude.com/docs/en/hooks

Wire up via Claude Code's `~/.claude/settings.json`. See
settings.json.example in this directory.

Environment variables:
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    If "1", block on any adapter error. Default: "1".
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "1") == "1"
ACS_VERSION = "0.1.0"


# Claude Code hook_event_name -> ACS step method
HOOK_MAP: dict[str, str] = {
    "SessionStart": "steps/sessionStart",
    "SessionEnd": "steps/sessionEnd",
    "UserPromptSubmit": "steps/userMessage",
    "PreToolUse": "steps/toolCallRequest",
    "PostToolUse": "steps/toolCallResult",
    "PreCompact": "steps/preCompact",
    "PostCompact": "steps/postCompact",
    "Notification": "steps/agentResponse",
    "Stop": "steps/sessionEnd",
    "SubagentStop": "steps/subagentStop",
}


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Build the ACS step payload from a Claude Code hook event."""
    name = event.get("hook_event_name", "")
    payload: dict[str, Any] = {
        "session_id": event.get("session_id", ""),
        "step_id": str(uuid.uuid4()),
        "cwd": event.get("cwd"),
        "transcript_path": event.get("transcript_path"),
        "permission_mode": event.get("permission_mode"),
    }
    # Drop None values to keep the payload clean
    payload = {k: v for k, v in payload.items() if v is not None}

    if name == "PreToolUse":
        payload["tool"] = {
            "name": event.get("tool_name", ""),
            "arguments": event.get("tool_input", {}),
        }
        payload["tool_use_id"] = event.get("tool_use_id")
    elif name == "PostToolUse":
        payload["tool"] = {
            "name": event.get("tool_name", ""),
            "arguments": event.get("tool_input", {}),
        }
        # Real Claude Code emits tool_response (object with stdout/stderr/...);
        # docs say tool_output (string). Accept either for forward-compat.
        payload["result"] = event.get("tool_response", event.get("tool_output"))
        payload["tool_use_id"] = event.get("tool_use_id")
        payload["duration_ms"] = event.get("duration_ms")
    elif name == "UserPromptSubmit":
        payload["content"] = event.get("prompt", "")
    elif name == "Notification":
        payload["content"] = event.get("message", "")
        payload["notification_type"] = event.get("notification_type")
    elif name == "SessionStart":
        payload["source"] = event.get("source")
        payload["model"] = event.get("model")
    elif name == "SessionEnd":
        payload["reason"] = event.get("reason")
    elif name in ("PreCompact", "PostCompact"):
        payload["trigger"] = event.get("trigger")
    elif name == "SubagentStop":
        payload["agent_id"] = event.get("agent_id")
        payload["agent_type"] = event.get("agent_type")

    return {k: v for k, v in payload.items() if v is not None}


def build_request(event: dict[str, Any]) -> dict[str, Any]:
    """Build an ACS-shaped JSON-RPC request envelope."""
    method = HOOK_MAP.get(event.get("hook_event_name", ""))
    if method is None:
        return {}
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": build_payload(event),
        "acs_version": ACS_VERSION,
        "request_id": str(uuid.uuid4()),
        "timestamp": int(time.time() * 1000),
        "metadata": {"source": "acs-adapter-claude-code"},
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


def translate_response(acs_response: dict[str, Any], hook_event: str) -> dict[str, Any]:
    """Translate an ACS decision envelope to Claude Code's expected output.

    Schema reference: https://code.claude.com/docs/en/hooks
    """
    result = acs_response.get("result", {})
    decision = (result.get("decision") or "").lower()
    reasoning = result.get("reasoning", "")
    modifications = result.get("modifications", {})

    # ----- PreToolUse: permissionDecision under hookSpecificOutput -----
    if hook_event == "PreToolUse":
        hso: dict[str, Any] = {"hookEventName": "PreToolUse"}
        if decision in PRETOOL_PERMISSION_MAP:
            hso["permissionDecision"] = PRETOOL_PERMISSION_MAP[decision]
            if reasoning:
                hso["permissionDecisionReason"] = reasoning
            return {"hookSpecificOutput": hso}
        if decision == "modify":
            # Claude Code's modify path: updatedInput
            overrides = modifications.get("parameter_overrides")
            if overrides is not None:
                hso["permissionDecision"] = "allow"
                hso["updatedInput"] = overrides
                if reasoning:
                    hso["permissionDecisionReason"] = reasoning
                return {"hookSpecificOutput": hso}
            # MODIFY without parameter_overrides on PreToolUse: substitute DENY
            hso["permissionDecision"] = "deny"
            hso["permissionDecisionReason"] = (
                f"MODIFY substituted to DENY (no parameter_overrides): {reasoning}"
            )
            return {"hookSpecificOutput": hso}
        # Unknown / empty decision: proceed
        return {}

    # ----- PostToolUse: top-level decision, optional updatedToolOutput -----
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

    # ----- UserPromptSubmit: decision block + additionalContext -----
    if hook_event == "UserPromptSubmit":
        if decision == "deny":
            return {
                "decision": "block",
                "reason": reasoning or "blocked by Guardian",
            }
        if decision in ("ask", "defer"):
            return {
                "decision": "block",
                "reason": f"{decision} on user prompt: {reasoning}",
            }
        # Modify on a prompt isn't expressible via this hook's contract;
        # Guardian-side rewrite would have to happen before submission.
        return {}

    # ----- Stop / SubagentStop -----
    if hook_event in ("Stop", "SubagentStop"):
        if decision == "deny":
            return {
                "decision": "block",
                "reason": reasoning or "blocked by Guardian",
            }
        return {}

    # ----- PreCompact -----
    if hook_event == "PreCompact":
        if decision == "deny":
            return {
                "decision": "block",
                "reason": reasoning or "compaction blocked by Guardian",
                "hookSpecificOutput": {"hookEventName": "PreCompact"},
            }
        return {}

    # ----- SessionStart / SessionEnd / PostCompact / Notification -----
    # Informational hooks: ACS records them, Claude Code does not gate on them.
    # If the Guardian wants to feed context back, additionalContext goes here.
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
        return 0  # not a hook we map; proceed

    try:
        request = build_request(event)
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
        return 0  # fail-open: proceed with no output
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
        # Informational hooks: fail-open is the only viable option (no block contract)
        return 0
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
