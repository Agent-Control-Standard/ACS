#!/usr/bin/env python3
"""
ACS adapter for Cursor hooks.

Translates a Cursor hook event (read from stdin as JSON) into an ACS
JSON-RPC request, sends it to a Guardian, and translates the ACS
response back to Cursor's expected output format.

Schema source: Cursor `create-hook` skill (~/.cursor/skills-cursor/create-hook/SKILL.md).

Cursor's hook protocol:
  - Per-event-name configuration in .cursor/hooks.json (or ~/.cursor/hooks.json)
  - JSON event piped to stdin
  - JSON response on stdout (event-specific output keys)
  - Exit 0 = success, exit 2 = block, other nonzero = fail-open unless failClosed
  - Per-hook `failClosed: true` makes adapter errors block the action

Because Cursor wires each hook to a specific event name in hooks.json, the
adapter takes the event name as argv[1] rather than relying on a field in
the stdin JSON (which Cursor's documented schema does not expose by a
single canonical field across all events).

Usage in hooks.json:
  {
    "command": "python3 /path/to/cursor_adapter.py preToolUse"
  }

Environment variables:
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    If "1", emit deny on adapter error. Default: "1".
                      (Cursor also honors `failClosed: true` in hooks.json.)
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


# Cursor hook event -> ACS step method
HOOK_MAP: dict[str, str] = {
    "sessionStart": "steps/sessionStart",
    "sessionEnd": "steps/sessionEnd",
    "stop": "steps/sessionEnd",
    "preToolUse": "steps/toolCallRequest",
    "postToolUse": "steps/toolCallResult",
    "postToolUseFailure": "steps/toolCallResult",
    "subagentStart": "steps/subagentStart",
    "subagentStop": "steps/subagentStop",
    "beforeShellExecution": "steps/toolCallRequest",
    "afterShellExecution": "steps/toolCallResult",
    "beforeMCPExecution": "steps/toolCallRequest",
    "afterMCPExecution": "steps/toolCallResult",
    "beforeReadFile": "steps/knowledgeRetrieval",
    "afterFileEdit": "steps/toolCallResult",
    "beforeSubmitPrompt": "steps/userMessage",
    "preCompact": "steps/preCompact",
    "afterAgentResponse": "steps/agentResponse",
    "afterAgentThought": "steps/agentResponse",
    "beforeTabFileRead": "steps/knowledgeRetrieval",
    "afterTabFileEdit": "steps/toolCallResult",
}


# Cursor's per-event output field naming (from SKILL.md):
#   preToolUse                 -> permission, user_message, agent_message, updated_input
#   postToolUse                -> additional_context, updated_mcp_tool_output (MCP)
#   subagentStart              -> permission, user_message
#   subagentStop               -> followup_message
#   beforeShellExecution       -> permission, user_message, agent_message
#   beforeMCPExecution         -> permission, user_message, agent_message
#
# Other events (lifecycle, etc.) are informational with no documented
# normative response keys; the adapter emits an empty object for those.

PERMISSION_EVENTS = {
    "preToolUse",
    "subagentStart",
    "beforeShellExecution",
    "beforeMCPExecution",
}

POST_TOOL_EVENTS = {
    "postToolUse",
    "postToolUseFailure",
    "afterMCPExecution",
}


def build_payload(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    """Build the ACS step payload from a Cursor hook event."""
    payload: dict[str, Any] = {
        "session_id": event.get("session_id") or event.get("conversation_id", ""),
        "step_id": str(uuid.uuid4()),
        "cwd": event.get("cwd") or event.get("workspace_path"),
    }
    payload = {k: v for k, v in payload.items() if v}

    if event_name in ("preToolUse", "postToolUse", "postToolUseFailure"):
        payload["tool"] = {
            "name": event.get("tool_name") or event.get("tool", ""),
            "arguments": event.get("tool_input") or event.get("arguments", {}),
        }
        if event_name != "preToolUse":
            payload["result"] = event.get("tool_output") or event.get("result")
    elif event_name in ("beforeShellExecution", "afterShellExecution"):
        payload["tool"] = {"name": "Shell", "arguments": {"command": event.get("command", "")}}
        if event_name == "afterShellExecution":
            payload["result"] = event.get("output") or event.get("result")
    elif event_name in ("beforeMCPExecution", "afterMCPExecution"):
        payload["tool"] = {
            "name": event.get("mcp_server", "") + ":" + event.get("mcp_tool", ""),
            "arguments": event.get("tool_input") or event.get("arguments", {}),
        }
        if event_name == "afterMCPExecution":
            payload["result"] = event.get("tool_output") or event.get("result")
    elif event_name in ("beforeReadFile", "beforeTabFileRead"):
        payload["source"] = event.get("file_path", "")
    elif event_name in ("afterFileEdit", "afterTabFileEdit"):
        payload["tool"] = {"name": "Edit", "arguments": {"file_path": event.get("file_path", "")}}
    elif event_name == "beforeSubmitPrompt":
        payload["content"] = event.get("prompt", "") or event.get("user_message", "")
    elif event_name in ("subagentStart", "subagentStop"):
        payload["subagent_type"] = event.get("subagent_type")
        payload["subagent_id"] = event.get("subagent_id")
    elif event_name in ("afterAgentResponse", "afterAgentThought"):
        payload["content"] = event.get("response", "") or event.get("thought", "")

    return {k: v for k, v in payload.items() if v is not None}


def build_request(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    method = HOOK_MAP.get(event_name)
    if method is None:
        return {}
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": build_payload(event_name, event),
        "acs_version": ACS_VERSION,
        "request_id": str(uuid.uuid4()),
        "timestamp": int(time.time() * 1000),
        "metadata": {"source": "acs-adapter-cursor", "cursor_event": event_name},
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


# ACS disposition -> Cursor permission value (for permission events)
PERMISSION_MAP: dict[str, str] = {
    "allow": "allow",
    "deny": "deny",
    "ask": "ask",
    "defer": "ask",  # Cursor has no defer; closest equivalent is ask
}


def translate_response(acs_response: dict[str, Any], event_name: str) -> dict[str, Any]:
    """Translate an ACS decision envelope to Cursor's expected output."""
    result = acs_response.get("result", {})
    decision = (result.get("decision") or "").lower()
    reasoning = result.get("reasoning", "")
    modifications = result.get("modifications", {})

    # ----- Permission events (preToolUse, subagentStart, beforeShellExecution, beforeMCPExecution) -----
    if event_name in PERMISSION_EVENTS:
        out: dict[str, Any] = {}
        if decision in PERMISSION_MAP:
            out["permission"] = PERMISSION_MAP[decision]
            if reasoning:
                out["user_message"] = reasoning
                out["agent_message"] = reasoning
            return out
        if decision == "modify":
            overrides = modifications.get("parameter_overrides")
            if overrides is not None and event_name == "preToolUse":
                # Cursor supports updated_input on preToolUse
                out["permission"] = "allow"
                out["updated_input"] = overrides
                if reasoning:
                    out["user_message"] = reasoning
                return out
            # No usable modification target: substitute deny with audit
            return {
                "permission": "deny",
                "user_message": f"MODIFY substituted to DENY: {reasoning}",
                "agent_message": f"MODIFY substituted to DENY: {reasoning}",
            }
        return {}

    # ----- Post-tool events: additional_context or updated_mcp_tool_output -----
    if event_name in POST_TOOL_EVENTS:
        if decision == "modify":
            if event_name == "afterMCPExecution":
                updated = modifications.get("modified_content")
                if updated is not None:
                    return {"updated_mcp_tool_output": str(updated)}
            # Other post-tool events don't have a modify-output field; use additional_context
            return {"additional_context": f"MODIFY received: {reasoning}"}
        if reasoning:
            return {"additional_context": reasoning}
        return {}

    # ----- subagentStop: followup_message (string) -----
    if event_name == "subagentStop":
        if decision == "deny":
            # No-op: subagent already stopped; emit followup_message with reasoning
            return {"followup_message": f"Subagent denied at stop: {reasoning}"}
        return {}

    # ----- beforeSubmitPrompt: no documented response keys; rely on exit code -----
    # If deny, exit 2 to block.
    if event_name == "beforeSubmitPrompt":
        return {"__exit_code": 2 if decision == "deny" else 0,
                "_reasoning": reasoning if decision == "deny" else None}

    # ----- Other events (lifecycle, file events, agent emissions): no normative gating -----
    return {}


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("acs-adapter: missing event name argument (usage: cursor_adapter.py <event_name>)\n")
        return 1
    event_name = sys.argv[1]

    raw = sys.stdin.read().strip()
    if not raw:
        return 0
    try:
        event = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"acs-adapter: invalid JSON on stdin: {e}\n")
        return _fail(event_name)

    if event_name not in HOOK_MAP:
        return 0

    try:
        request = build_request(event_name, event)
        response = call_guardian(request)
        out = translate_response(response, event_name)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return _fail(event_name)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(event_name)

    # Special-case: beforeSubmitPrompt uses exit code rather than stdout JSON
    if event_name == "beforeSubmitPrompt":
        exit_code = out.pop("__exit_code", 0)
        reasoning = out.pop("_reasoning", None)
        if reasoning:
            sys.stderr.write(f"acs-adapter: blocking prompt: {reasoning}\n")
        return exit_code

    if out:
        json.dump(out, sys.stdout)
        sys.stdout.write("\n")
    return 0


def _fail(event_name: str = "") -> int:
    """Apply fail posture."""
    if not DEFAULT_DENY:
        return 0  # fail-open: proceed
    if event_name in PERMISSION_EVENTS:
        json.dump(
            {"permission": "deny", "user_message": "ACS adapter: Guardian unreachable",
             "agent_message": "ACS adapter: Guardian unreachable"},
            sys.stdout,
        )
        sys.stdout.write("\n")
        return 0
    if event_name == "beforeSubmitPrompt":
        sys.stderr.write("acs-adapter: prompt blocked (Guardian unreachable)\n")
        return 2  # exit 2 = block
    # No documented block contract for other events; fail-open by necessity
    return 0


if __name__ == "__main__":
    sys.exit(main())
