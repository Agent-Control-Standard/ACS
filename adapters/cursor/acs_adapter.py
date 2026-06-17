#!/usr/bin/env python3
"""
ACS adapter for Cursor hooks.

Translates a Cursor hook event (read from stdin as JSON) into an ACS
JSON-RPC request, sends it to a Guardian, and translates the ACS
response back to Cursor's expected output format.

Schema source: Cursor `create-hook` skill (~/.cursor/skills-cursor/create-hook/SKILL.md).
ACS schema source: Agent-Control-Standard/ACS specification/v0.1.0/

Cursor's hook protocol:
  - Per-event-name configuration in .cursor/hooks.json (or ~/.cursor/hooks.json)
  - JSON event piped to stdin
  - JSON response on stdout (event-specific output keys)
  - Exit 0 = success, exit 2 = block, other nonzero = fail-open unless failClosed
  - Per-hook `failClosed: true` makes adapter errors block the action

Because Cursor wires each hook to a specific event name in hooks.json, the
adapter takes the event name as argv[1] rather than relying on a field in
the stdin JSON.

Usage in hooks.json:
  { "command": "python3 /path/to/acs_adapter.py preToolUse" }

Environment variables:
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    If "1", emit deny on adapter error or unknown
                      Guardian disposition. Default: "1".
                      (Cursor also honors `failClosed: true` in hooks.json.)
  ACS_AGENT_ID        Explicit agent_id for metadata. If unset, derived
                      from workspace path as `cursor:<sha8(cwd)>`.
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


# Cursor hook event -> ACS step method.
# beforeReadFile / beforeTabFileRead intentionally NOT mapped to
# steps/knowledgeRetrieval: that hook's payload schema requires
# {query, results}, neither of which a file-read event exposes. A
# future ACS hook (e.g. steps/fileAccess) would be the right home; for
# now, the adapter does not forward these and Cursor's hooks.json
# should not wire the adapter to them.
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
    "afterFileEdit": "steps/toolCallResult",
    "beforeSubmitPrompt": "steps/userMessage",
    "preCompact": "steps/preCompact",
    "afterAgentResponse": "steps/agentResponse",
    "afterAgentThought": "steps/agentResponse",
    "afterTabFileEdit": "steps/toolCallResult",
}


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
    "afterShellExecution",
    "afterFileEdit",
    "afterTabFileEdit",
}


def _iso8601_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _agent_id(event: dict[str, Any]) -> str:
    explicit = os.environ.get("ACS_AGENT_ID")
    if explicit:
        return explicit
    cwd = event.get("cwd") or event.get("workspace_path") or os.environ.get("PWD") or ""
    if cwd:
        return f"cursor:{hashlib.sha256(cwd.encode()).hexdigest()[:8]}"
    return "cursor:unknown"


def _session_id(event: dict[str, Any]) -> str:
    """Cursor exposes session_id or conversation_id depending on event.

    request-envelope.json:66 wants UUID format. We derive a stable UUID5
    from whatever Cursor gives us so the same conversation always maps
    to the same UUID. If Cursor sends a UUID directly, we use it as-is.
    """
    raw = event.get("session_id") or event.get("conversation_id") or ""
    if not raw:
        return ""
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cursor:{raw}"))


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _outputs_list(raw: Any) -> list[dict[str, Any]]:
    """tool-call-result.json wants outputs as array of {value, provenance?}."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item if isinstance(item, dict) and "value" in item else {"value": item} for item in raw]
    return [{"value": raw}]


def build_payload(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    """Build the hook-specific payload (params.payload).

    Each branch returns a payload that validates against the
    corresponding `specification/v0.1.0/hooks/<hook>.json` schema.
    """
    if event_name == "preToolUse":
        return {
            "tool": {"name": event.get("tool_name") or event.get("tool", "")},
            "arguments": _wrap_arguments(event.get("tool_input") or event.get("arguments") or {}),
        }

    if event_name == "beforeShellExecution":
        return {
            "tool": {"name": "Shell"},
            "arguments": _wrap_arguments({"command": event.get("command", "")}),
        }

    if event_name == "beforeMCPExecution":
        return {
            "tool": {
                "name": f"{event.get('mcp_server', '')}:{event.get('mcp_tool', '')}",
                "provider": event.get("mcp_server", ""),
            },
            "arguments": _wrap_arguments(event.get("tool_input") or event.get("arguments") or {}),
        }

    if event_name in ("postToolUse", "postToolUseFailure"):
        exit_status = "failure" if event_name == "postToolUseFailure" else "success"
        return {
            "tool": {"name": event.get("tool_name") or event.get("tool", "")},
            "exit_status": exit_status,
            "outputs": _outputs_list(event.get("tool_output") or event.get("result")),
        }

    if event_name == "afterShellExecution":
        return {
            "tool": {"name": "Shell"},
            "exit_status": "failure" if event.get("exit_code", 0) else "success",
            "outputs": _outputs_list(event.get("output") or event.get("result")),
        }

    if event_name == "afterMCPExecution":
        return {
            "tool": {
                "name": f"{event.get('mcp_server', '')}:{event.get('mcp_tool', '')}",
                "provider": event.get("mcp_server", ""),
            },
            "exit_status": "success",
            "outputs": _outputs_list(event.get("tool_output") or event.get("result")),
        }

    if event_name in ("afterFileEdit", "afterTabFileEdit"):
        return {
            "tool": {"name": "Edit"},
            "exit_status": "success",
            "outputs": _outputs_list({"file_path": event.get("file_path", "")}),
        }

    if event_name == "beforeSubmitPrompt":
        # user-message.json: content array of {type, value, provenance?}
        return {
            "content": [
                {"type": "text", "value": event.get("prompt") or event.get("user_message", "")}
            ],
        }

    if event_name in ("afterAgentResponse", "afterAgentThought"):
        return {
            "content": [
                {"type": "text", "value": event.get("response") or event.get("thought", "")}
            ],
        }

    if event_name == "sessionStart":
        out: dict[str, Any] = {}
        if event.get("workspace_path") or event.get("cwd"):
            out["platform_context"] = {
                "workspace_path": event.get("workspace_path") or event.get("cwd")
            }
        return out

    if event_name in ("sessionEnd", "stop"):
        # session-end.json: reason enum
        raw = (event.get("reason") or "").lower()
        return {"reason": raw if raw in {"completed", "cancelled", "error", "timeout", "abandoned"} else "completed"}

    if event_name == "subagentStart":
        # subagent-start.json requires subagent_session_id, parent_session_id,
        # parent_step_id, intent_derivation. Cursor exposes subagent_id, not
        # all of these — emit a degraded but schema-valid payload using uuid5
        # for the synthetic IDs the framework doesn't provide.
        sub_raw = event.get("subagent_id", "")
        parent_raw = event.get("parent_session_id") or _session_id(event) or "unknown-parent"
        return {
            "subagent_session_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cursor-subagent:{sub_raw or uuid.uuid4()}")),
            "parent_session_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cursor-parent:{parent_raw}")) if not _looks_like_uuid(parent_raw) else parent_raw,
            "parent_step_id": str(uuid.uuid4()),
            "intent_derivation": "derived_from_parent",
            "subagent_descriptor": {
                "agent_id": sub_raw,
                "agent_name": event.get("subagent_type", ""),
            } if sub_raw else {},
        }

    if event_name == "subagentStop":
        # subagent-stop.json requires subagent_session_id, outcome, final_chain_hash.
        sub_raw = event.get("subagent_id", "")
        # Synthetic final_chain_hash because Cursor doesn't expose one — it's
        # a sha256 of (subagent_id || timestamp) so it satisfies the 64-hex
        # pattern. Real deployments compute this from the actual ContextEntry chain.
        synthetic_hash = hashlib.sha256(f"cursor:{sub_raw}:{_iso8601_now()}".encode()).hexdigest()
        return {
            "subagent_session_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cursor-subagent:{sub_raw or uuid.uuid4()}")),
            "outcome": (event.get("outcome") or "completed"),
            "final_chain_hash": synthetic_hash,
        }

    if event_name == "preCompact":
        # pre-compact.json requires entries_to_compact (min 1), triggered_by.
        # Cursor's preCompact does not expose step_ids; emit a single
        # placeholder entry so the payload validates and the Guardian sees
        # the compaction is happening.
        return {
            "entries_to_compact": [event.get("session_id") or "unknown"],
            "triggered_by": (event.get("trigger") or "framework_initiated"),
        }

    return {}


def _looks_like_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def build_request(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    method = HOOK_MAP.get(event_name)
    if method is None:
        return {}

    session_id = _session_id(event)
    if not session_id:
        return {}

    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": session_id,
        "platform": "cursor",
        "cursor_event": event_name,
    }
    if event.get("cwd") or event.get("workspace_path"):
        metadata["workspace_path"] = event.get("cwd") or event.get("workspace_path")

    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": _iso8601_now(),
            "metadata": metadata,
            "payload": build_payload(event_name, event),
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


PERMISSION_MAP: dict[str, str] = {
    "allow": "allow",
    "deny": "deny",
    "ask": "ask",
    "defer": "ask",  # Cursor has no native defer; closest equivalent is ask
}

KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


def translate_response(acs_response: dict[str, Any], event_name: str) -> dict[str, Any]:
    """Translate an ACS decision envelope to Cursor's expected output.

    Unknown / missing decisions respect ACS_DEFAULT_DENY: on True, the
    adapter emits a deny in the event's native shape rather than silently
    proceeding.
    """
    result = acs_response.get("result", {})
    decision = (result.get("decision") or "").lower()
    reasoning = result.get("reasoning", "")
    modifications = result.get("modifications", {})

    if decision not in KNOWN_DECISIONS and DEFAULT_DENY:
        reason = f"unknown Guardian disposition '{decision}' (default-deny)"
        if event_name in PERMISSION_EVENTS:
            return {"permission": "deny", "user_message": reason, "agent_message": reason}
        if event_name == "beforeSubmitPrompt":
            return {"__exit_code": 2, "_reasoning": reason}

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
                out["permission"] = "allow"
                out["updated_input"] = overrides
                if reasoning:
                    out["user_message"] = reasoning
                return out
            return {
                "permission": "deny",
                "user_message": f"MODIFY substituted to DENY: {reasoning}",
                "agent_message": f"MODIFY substituted to DENY: {reasoning}",
            }
        return {}

    if event_name in POST_TOOL_EVENTS:
        if decision == "modify":
            if event_name == "afterMCPExecution":
                updated = modifications.get("modified_content")
                if updated is not None:
                    return {"updated_mcp_tool_output": str(updated)}
            return {"additional_context": f"MODIFY received: {reasoning}"}
        if reasoning:
            return {"additional_context": reasoning}
        return {}

    if event_name == "subagentStop":
        if decision == "deny":
            return {"followup_message": f"Subagent denied at stop: {reasoning}"}
        return {}

    if event_name == "beforeSubmitPrompt":
        return {
            "__exit_code": 2 if decision == "deny" else 0,
            "_reasoning": reasoning if decision == "deny" else None,
        }

    return {}


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("acs-adapter: missing event name argument (usage: acs_adapter.py <event_name>)\n")
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
        if not request:
            sys.stderr.write(f"acs-adapter: could not build request for {event_name}\n")
            return _fail(event_name)
        response = call_guardian(request)
        out = translate_response(response, event_name)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return _fail(event_name)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(event_name)

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
    if not DEFAULT_DENY:
        return 0
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
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
