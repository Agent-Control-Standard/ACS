#!/usr/bin/env python3
"""
ACS adapter for Cursor hooks.

Translates a Cursor hook event into a signed ACS JSON-RPC request,
sends it to a Guardian, and translates the ACS response back to
Cursor's expected output format.

Wire-format ground truth: Agent-Control-Standard/ACS specification/v0.1.0/

Note on payload completeness: Cursor does not expose all fields the
ACS v0.1.0 hook schemas require for subagentStart, subagentStop, and
preCompact. The adapter emits schema-valid payloads using deterministic
uuid5/sha256 derivations for the missing required fields. These are
syntactically valid but semantically synthetic — a Guardian seeing
them gets a placeholder, not a real subagent or compaction record.
This is a Cursor schema gap that ACS cannot close on its side. See
the README for the full per-hook honesty table.

Usage in hooks.json:
  { "command": "python3 /path/to/acs_adapter.py preToolUse" }

Environment variables (same defaults / semantics as the Claude Code adapter):
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    "1" = fail-closed. Default "0" (spec default per §6.4).
                      Cursor also honors per-hook `failClosed: true` in hooks.json.
  ACS_HMAC_SECRET     Shared secret for HMAC-SHA256 signing per §10. Unset = no signing (local dev).
  ACS_AGENT_ID        Explicit agent_id; defaults to cursor:<sha8(workspace)>.
  ACS_HANDSHAKE       "0" disables handshake. Default "1".
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
from acs_common import (  # noqa: E402
    ACS_VERSION,
    audit_event,
    coerce_uuid,
    do_handshake,
    iso8601_now,
    sign_envelope,
    verify_signature,
)


GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
HANDSHAKE_ENABLED = os.environ.get("ACS_HANDSHAKE", "1") == "1"


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


PERMISSION_EVENTS = {"preToolUse", "subagentStart", "beforeShellExecution", "beforeMCPExecution"}
POST_TOOL_EVENTS = {
    "postToolUse", "postToolUseFailure", "afterMCPExecution",
    "afterShellExecution", "afterFileEdit", "afterTabFileEdit",
}


def _agent_id(event: dict[str, Any]) -> str:
    explicit = os.environ.get("ACS_AGENT_ID")
    if explicit:
        return explicit
    cwd = event.get("cwd") or event.get("workspace_path") or os.environ.get("PWD") or ""
    if cwd:
        return f"cursor:{hashlib.sha256(cwd.encode()).hexdigest()[:8]}"
    return "cursor:unknown"


def _session_id(event: dict[str, Any]) -> str:
    raw = event.get("session_id") or event.get("conversation_id") or ""
    return coerce_uuid(raw, namespace_prefix="cursor") if raw else ""


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _outputs_list(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item if isinstance(item, dict) and "value" in item else {"value": item} for item in raw]
    return [{"value": raw}]


def _tool_use_request_id(tool_call_id: str | None) -> str | None:
    if not tool_call_id:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cursor:tool_use:{tool_call_id}"))


def build_payload(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
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
            "tool": {"name": f"{event.get('mcp_server', '')}:{event.get('mcp_tool', '')}",
                     "provider": event.get("mcp_server", "")},
            "arguments": _wrap_arguments(event.get("tool_input") or event.get("arguments") or {}),
        }

    if event_name in ("postToolUse", "postToolUseFailure"):
        payload = {
            "tool": {"name": event.get("tool_name") or event.get("tool", "")},
            "exit_status": "failure" if event_name == "postToolUseFailure" else "success",
            "outputs": _outputs_list(event.get("tool_output") or event.get("result")),
        }
        ref = _tool_use_request_id(event.get("tool_call_id") or event.get("tool_use_id"))
        if ref:
            payload["request_id_ref"] = ref
        return payload

    if event_name == "afterShellExecution":
        payload = {
            "tool": {"name": "Shell"},
            "exit_status": "failure" if event.get("exit_code", 0) else "success",
            "outputs": _outputs_list(event.get("output") or event.get("result")),
        }
        ref = _tool_use_request_id(event.get("execution_id"))
        if ref:
            payload["request_id_ref"] = ref
        return payload

    if event_name == "afterMCPExecution":
        payload = {
            "tool": {"name": f"{event.get('mcp_server', '')}:{event.get('mcp_tool', '')}",
                     "provider": event.get("mcp_server", "")},
            "exit_status": "success",
            "outputs": _outputs_list(event.get("tool_output") or event.get("result")),
        }
        ref = _tool_use_request_id(event.get("call_id"))
        if ref:
            payload["request_id_ref"] = ref
        return payload

    if event_name in ("afterFileEdit", "afterTabFileEdit"):
        return {
            "tool": {"name": "Edit"},
            "exit_status": "success",
            "outputs": _outputs_list({"file_path": event.get("file_path", "")}),
        }

    if event_name == "beforeSubmitPrompt":
        return {"content": [{"type": "text",
                             "value": event.get("prompt") or event.get("user_message", "")}]}

    if event_name in ("afterAgentResponse", "afterAgentThought"):
        return {"content": [{"type": "text",
                             "value": event.get("response") or event.get("thought", "")}]}

    if event_name == "sessionStart":
        out: dict[str, Any] = {}
        if event.get("workspace_path") or event.get("cwd"):
            out["platform_context"] = {"workspace_path": event.get("workspace_path") or event.get("cwd")}
        return out

    if event_name in ("sessionEnd", "stop"):
        raw = (event.get("reason") or "").lower()
        return {"reason": raw if raw in {"completed", "cancelled", "error", "timeout", "abandoned"} else "completed"}

    if event_name == "subagentStart":
        # SYNTHETIC: Cursor does not expose these required ACS fields. The
        # payload satisfies the schema using deterministic uuid5 derivations
        # but does not carry real subagent-boundary semantics. Documented
        # in adapters/cursor/README.md "Per-hook honesty table".
        sub_raw = event.get("subagent_id", "")
        parent_raw = event.get("parent_session_id") or _session_id(event) or "unknown-parent"
        parent_session = parent_raw if _looks_like_uuid(parent_raw) else str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"cursor-parent:{parent_raw}"))
        return {
            "subagent_session_id": str(uuid.uuid5(uuid.NAMESPACE_URL,
                                                  f"cursor-subagent:{sub_raw or 'unknown'}")),
            "parent_session_id": parent_session,
            "parent_step_id": str(uuid.uuid4()),
            "intent_derivation": "derived_from_parent",
            "subagent_descriptor": ({"agent_id": sub_raw, "agent_name": event.get("subagent_type", "")}
                                    if sub_raw else {}),
        }

    if event_name == "subagentStop":
        # SYNTHETIC: final_chain_hash is fabricated; Cursor does not expose one.
        sub_raw = event.get("subagent_id", "")
        synthetic_hash = hashlib.sha256(f"cursor:{sub_raw}:{iso8601_now()}".encode()).hexdigest()
        return {
            "subagent_session_id": str(uuid.uuid5(uuid.NAMESPACE_URL,
                                                  f"cursor-subagent:{sub_raw or 'unknown'}")),
            "outcome": (event.get("outcome") or "completed"),
            "final_chain_hash": synthetic_hash,
        }

    if event_name == "preCompact":
        # SYNTHETIC: entries_to_compact is a placeholder (Cursor does not
        # expose the step_ids being compacted).
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

    if method == "steps/toolCallRequest":
        ref = _tool_use_request_id(event.get("tool_call_id") or event.get("tool_use_id")
                                   or event.get("execution_id"))
        request_id = ref or str(uuid.uuid4())
    else:
        request_id = str(uuid.uuid4())

    envelope = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": request_id,
            "timestamp": iso8601_now(),
            "metadata": metadata,
            "payload": build_payload(event_name, event),
        },
    }
    sign_envelope(envelope, session_id=session_id)
    return envelope


def _maybe_handshake(event: dict[str, Any]) -> None:
    if not HANDSHAKE_ENABLED:
        return
    sid = _session_id(event)
    if not sid:
        return
    do_handshake(
        guardian_url=GUARDIAN_URL,
        session_id=sid,
        agent_id=_agent_id(event),
        platform="cursor",
        methods_implemented=list(HOOK_MAP.values()),
    )


def call_guardian(request: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(request).encode("utf-8")
    req = urllib.request.Request(
        GUARDIAN_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


PERMISSION_MAP: dict[str, str] = {"allow": "allow", "deny": "deny", "ask": "ask", "defer": "ask"}
KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


def translate_response(acs_response: dict[str, Any], event_name: str) -> dict[str, Any]:
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
            return {"permission": "deny",
                    "user_message": f"MODIFY substituted to DENY: {reasoning}",
                    "agent_message": f"MODIFY substituted to DENY: {reasoning}"}
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
        return {"__exit_code": 2 if decision == "deny" else 0,
                "_reasoning": reasoning if decision == "deny" else None}

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

    _maybe_handshake(event)

    request = None
    try:
        request = build_request(event_name, event)
        if not request:
            sys.stderr.write(f"acs-adapter: could not build request for {event_name}\n")
            return _fail(event_name, _session_id(event))
        response = call_guardian(request)

        if not verify_signature(response, session_id=_session_id(event)):
            sys.stderr.write("acs-adapter: response signature invalid\n")
            return _fail(event_name, _session_id(event))

        out = translate_response(response, event_name)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return _fail(event_name, _session_id(event),
                     request_id=(request or {}).get("params", {}).get("request_id"),
                     method=(request or {}).get("method"))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(event_name, _session_id(event))

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


def _fail(event_name: str = "", session_id: str | None = None, **audit_extras) -> int:
    if DEFAULT_DENY:
        msg = "ACS adapter: decision-failure (default-deny)"
        if event_name in PERMISSION_EVENTS:
            json.dump({"permission": "deny", "user_message": msg, "agent_message": msg}, sys.stdout)
            sys.stdout.write("\n")
            audit_event("decision_failure_fail_closed",
                        event=event_name, session_id=session_id, **audit_extras)
            return 0
        if event_name == "beforeSubmitPrompt":
            sys.stderr.write("acs-adapter: prompt blocked (decision-failure)\n")
            audit_event("decision_failure_fail_closed",
                        event=event_name, session_id=session_id, **audit_extras)
            return 2
        audit_event("decision_failure_fail_closed",
                    event=event_name, session_id=session_id, **audit_extras)
        return 0

    audit_event("fail_open_bypass",
                event=event_name, session_id=session_id, **audit_extras)
    return 0


if __name__ == "__main__":
    sys.exit(main())
