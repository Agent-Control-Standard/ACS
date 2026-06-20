#!/usr/bin/env python3
"""
ACS adapter for Cursor hooks.

Translates a Cursor hook event into a signed ACS JSON-RPC request,
sends it to a Guardian, and translates the ACS response back to
Cursor's expected output format.

Wire-format ground truth: Agent-Control-Standard/ACS specification/v0.1.0/

Note on payload completeness: Cursor does not expose every field ACS
v0.1.0 hook schemas require.

  - `subagentStart` — three of four required fields (subagent_session_id,
    parent_session_id, parent_step_id) are populated from real session
    data via deterministic UUID5 and the adapter's session-state tracking
    of the last step_id. The fourth, `intent_derivation`, is hardcoded to
    `derived_from_parent` (the defensible default for IDE-spawned subagents).
  - `preCompact` — both required fields are real: `entries_to_compact` is
    the list of step_ids the adapter has observed in this session;
    `triggered_by` comes from Cursor's `trigger` field.
  - `subagentStop` — NOT forwarded. The required `final_chain_hash` is
    genuinely unknowable (Cursor maintains no chain). Better to omit than
    to fabricate.

See the README per-hook honesty table for the full mapping.

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
from typing import Any, Callable


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
from acs_common import (  # noqa: E402
    ACS_VERSION,
    audit_event,
    coerce_uuid,
    ensure_session_handshake,
    guardian_error_cause,
    iso8601_now,
    load_session_state,
    record_step,
    save_session_state,
    sign_envelope,
    validate_guardian_url,
    verify_signature,
)


GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
HANDSHAKE_ENABLED = os.environ.get("ACS_HANDSHAKE", "1") == "1"


# ─── Hook taxonomy ──────────────────────────────────────────────────────────

# Cursor hook event -> ACS step method.
#
# Intentionally OMITTED from this map (documented gap, not synthesis):
#   subagentStop — `final_chain_hash` (64-hex SHA-256 of the subagent's
#                  ContextEntry chain) is genuinely unknowable because
#                  Cursor does not maintain a chain on its side. Emitting
#                  a fabricated hash would be schema-valid but
#                  semantically meaningless. Cursor's subagentStop event
#                  is therefore not forwarded. The Cursor README per-hook
#                  honesty table documents the gap.
HOOK_MAP: dict[str, str] = {
    "sessionStart":         "steps/sessionStart",
    "sessionEnd":           "steps/sessionEnd",
    "stop":                 "steps/sessionEnd",
    "preToolUse":           "steps/toolCallRequest",
    "postToolUse":          "steps/toolCallResult",
    "postToolUseFailure":   "steps/toolCallResult",
    "subagentStart":        "steps/subagentStart",
    "beforeShellExecution": "steps/toolCallRequest",
    "afterShellExecution":  "steps/toolCallResult",
    "beforeMCPExecution":   "steps/toolCallRequest",
    "afterMCPExecution":    "steps/toolCallResult",
    "afterFileEdit":        "steps/toolCallResult",
    "beforeSubmitPrompt":   "steps/userMessage",
    "preCompact":           "steps/preCompact",
    "afterAgentResponse":   "steps/agentResponse",
    "afterAgentThought":    "steps/agentResponse",
    "afterTabFileEdit":     "steps/toolCallResult",
}

# Cursor events whose deny shape is `{"permission": "deny", ...}`
# (vs `beforeSubmitPrompt` which uses exit code 2, and post-tool events
# which only carry `additional_context`).
PERMISSION_EVENTS = frozenset({
    "preToolUse", "subagentStart", "beforeShellExecution", "beforeMCPExecution",
})

POST_TOOL_EVENTS = frozenset({
    "postToolUse", "postToolUseFailure", "afterMCPExecution",
    "afterShellExecution", "afterFileEdit", "afterTabFileEdit",
})

PERMISSION_MAP: dict[str, str] = {
    "allow": "allow", "deny": "deny", "ask": "ask", "defer": "ask",  # no native defer
}

KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})

SESSION_END_REASONS = frozenset({"completed", "cancelled", "error", "timeout", "abandoned"})


# ─── Response writers — one definition each, used everywhere ──────────────

def _emit(payload: dict[str, Any]) -> None:
    """Single point where the adapter writes to stdout. Idempotent on
    empty dict. beforeSubmitPrompt uses internal __exit_code/_reasoning
    keys (handled in main) and never reaches this writer with them."""
    if not payload:
        return
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def _permission_response(decision: str, message: str = "",
                          updated_input: dict | None = None) -> dict[str, Any]:
    """Cursor's permission-event response shape: top-level `permission`
    plus optional user/agent messages and updated_input (preToolUse only)."""
    out: dict[str, Any] = {"permission": decision}
    if message:
        out["user_message"] = message
        out["agent_message"] = message
    if updated_input is not None:
        out["updated_input"] = updated_input
    return out


def _post_tool_response(additional_context: str | None = None,
                         updated_mcp_tool_output: str | None = None) -> dict[str, Any]:
    """Cursor post-tool event response — only `additional_context` and
    (for afterMCPExecution) `updated_mcp_tool_output`."""
    out: dict[str, Any] = {}
    if additional_context:
        out["additional_context"] = additional_context
    if updated_mcp_tool_output is not None:
        out["updated_mcp_tool_output"] = updated_mcp_tool_output
    return out


# ─── Helpers ────────────────────────────────────────────────────────────────

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


def _workspace(event: dict[str, Any]) -> str | None:
    """Workspace identifier folded into the session-state file key so
    two Cursor windows on different projects can't collide on a shared
    non-UUID conversation_id."""
    return event.get("workspace_path") or event.get("cwd") or None


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    """tool-call-request.json:26-37 — each arg is {value, provenance?}."""
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _outputs_list(raw: Any) -> list[dict[str, Any]]:
    """tool-call-result.json wants outputs as array of {value, provenance?}."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item if isinstance(item, dict) and "value" in item else {"value": item} for item in raw]
    return [{"value": raw}]


def _tool_use_request_id(tool_call_id: str | None) -> str | None:
    """Deterministic UUID5 so postToolUse can carry request_id_ref linking
    back to the originating preToolUse (per tool-call-result.json:19-23)."""
    if not tool_call_id:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cursor:tool_use:{tool_call_id}"))


# ─── Payload builders — dispatch table, one function per Cursor event ─────

def _payload_pretool(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": {"name": event.get("tool_name") or event.get("tool", "")},
        "arguments": _wrap_arguments(event.get("tool_input") or event.get("arguments") or {}),
    }


def _payload_before_shell(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": {"name": "Shell"},
        "arguments": _wrap_arguments({"command": event.get("command", "")}),
    }


def _payload_before_mcp(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": {"name": f"{event.get('mcp_server', '')}:{event.get('mcp_tool', '')}",
                 "provider": event.get("mcp_server", "")},
        "arguments": _wrap_arguments(event.get("tool_input") or event.get("arguments") or {}),
    }


def _payload_posttool(event: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "tool": {"name": event.get("tool_name") or event.get("tool", "")},
        "exit_status": "failure" if event.get("hook_event_name") == "postToolUseFailure"
                       or event.get("_event_name") == "postToolUseFailure" else "success",
        "outputs": _outputs_list(event.get("tool_output") or event.get("result")),
    }
    ref = _tool_use_request_id(event.get("tool_call_id") or event.get("tool_use_id"))
    if ref:
        payload["request_id_ref"] = ref
    return payload


def _payload_after_shell(event: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "tool": {"name": "Shell"},
        "exit_status": "failure" if event.get("exit_code", 0) else "success",
        "outputs": _outputs_list(event.get("output") or event.get("result")),
    }
    ref = _tool_use_request_id(event.get("execution_id"))
    if ref:
        payload["request_id_ref"] = ref
    return payload


def _payload_after_mcp(event: dict[str, Any]) -> dict[str, Any]:
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


def _payload_file_edit(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": {"name": "Edit"},
        "exit_status": "success",
        "outputs": _outputs_list({"file_path": event.get("file_path", "")}),
    }


def _payload_before_submit_prompt(event: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text",
                         "value": event.get("prompt") or event.get("user_message", "")}]}


def _payload_after_agent(event: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text",
                         "value": event.get("response") or event.get("thought", "")}]}


def _payload_session_start(event: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if event.get("workspace_path") or event.get("cwd"):
        out["platform_context"] = {"workspace_path": event.get("workspace_path") or event.get("cwd")}
    return out


def _payload_session_end(event: dict[str, Any]) -> dict[str, Any]:
    raw = (event.get("reason") or "").lower()
    return {"reason": raw if raw in SESSION_END_REASONS else "completed"}


def _payload_subagent_start(event: dict[str, Any]) -> dict[str, Any]:
    """All four schema-required fields, populated from real session data
    where possible. See Cursor README 'Per-hook honesty table'."""
    sub_raw = event.get("subagent_id", "")
    sid = _session_id(event)
    st = load_session_state(sid, workspace=_workspace(event))
    parent_step_id = st.get("last_step_id") or sid
    payload = {
        "subagent_session_id": str(uuid.uuid5(
            uuid.NAMESPACE_URL, f"cursor-subagent:{sid}:{sub_raw or 'unknown'}")),
        "parent_session_id": sid,
        "parent_step_id": parent_step_id,
        # Cursor IDE subagents are dispatched by the parent agent
        # (Composer/Agent panel routing), inheriting the parent's
        # context. derived_from_parent is the defensible default.
        "intent_derivation": "derived_from_parent",
    }
    if sub_raw:
        payload["subagent_descriptor"] = {
            "agent_id": sub_raw,
            "agent_name": event.get("subagent_type", ""),
        }
    return payload


def _payload_precompact(event: dict[str, Any]) -> dict[str, Any]:
    """entries_to_compact: real step_ids the adapter has observed in this
    session. Cursor doesn't tell us WHICH entries it intends to compact,
    but the entries actually IN the session are an honest superset
    (compaction always operates on something already observed)."""
    sid = _session_id(event)
    st = load_session_state(sid, workspace=_workspace(event))
    seen = list(st.get("seen_step_ids") or [])
    if not seen:
        # No prior steps recorded — adapter wired without preceding hooks.
        # Fall back to the session_id as a single placeholder entry.
        seen = [sid]
    return {
        "entries_to_compact": seen,
        "triggered_by": (event.get("trigger") or "framework_initiated"),
    }


_PAYLOAD_BUILDERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "preToolUse":           _payload_pretool,
    "beforeShellExecution": _payload_before_shell,
    "beforeMCPExecution":   _payload_before_mcp,
    "postToolUse":          _payload_posttool,
    "postToolUseFailure":   _payload_posttool,
    "afterShellExecution":  _payload_after_shell,
    "afterMCPExecution":    _payload_after_mcp,
    "afterFileEdit":        _payload_file_edit,
    "afterTabFileEdit":     _payload_file_edit,
    "beforeSubmitPrompt":   _payload_before_submit_prompt,
    "afterAgentResponse":   _payload_after_agent,
    "afterAgentThought":    _payload_after_agent,
    "sessionStart":         _payload_session_start,
    "sessionEnd":           _payload_session_end,
    "stop":                 _payload_session_end,
    "subagentStart":        _payload_subagent_start,
    "preCompact":           _payload_precompact,
}


def build_payload(event_name: str, event: dict[str, Any]) -> dict[str, Any]:
    builder = _PAYLOAD_BUILDERS.get(event_name)
    if not builder:
        return {}
    # _payload_posttool branches on event_name; thread it through
    if event_name in ("postToolUse", "postToolUseFailure"):
        event = {**event, "_event_name": event_name}
    return builder(event)


# ─── Envelope construction ──────────────────────────────────────────────────

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

    # For *Request methods, pin request_id deterministically so a matching
    # *Result can populate request_id_ref pointing back at it.
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
    """Called on every hook event. Idempotent per session via disk
    cache — only the first event of a session actually POSTs
    handshake/hello. See ensure_session_handshake's docstring."""
    if not HANDSHAKE_ENABLED:
        return
    sid = _session_id(event)
    if not sid:
        return
    ensure_session_handshake(
        guardian_url=GUARDIAN_URL,
        session_id=sid,
        agent_id=_agent_id(event),
        platform="cursor",
        methods_implemented=list(HOOK_MAP.values()),
    )


def call_guardian(request: dict[str, Any]) -> dict[str, Any]:
    validate_guardian_url(GUARDIAN_URL)  # SSRF: refuse file://, ftp://, etc.
    body = json.dumps(request).encode("utf-8")
    req = urllib.request.Request(
        GUARDIAN_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ─── Response translation — dispatch table by event category ──────────────
#
# Cursor's response shapes group naturally into 4 categories:
#   - permission events (preToolUse, subagentStart, beforeShellExecution,
#     beforeMCPExecution): {"permission": ..., "user_message": ..., "agent_message": ...,
#     "updated_input": ...}
#   - post-tool events (postToolUse, postToolUseFailure, afterShellExecution,
#     afterMCPExecution, afterFileEdit, afterTabFileEdit): {"additional_context": ...,
#     "updated_mcp_tool_output": ...}
#   - beforeSubmitPrompt: uses exit code 2 (not stdout) to block; carries
#     internal __exit_code/_reasoning keys consumed by main()
#   - everything else: no response shape (Stop, SessionStart, SessionEnd, etc.)

def _translate_permission(decision: str, reasoning: str,
                           modifications: dict, event_name: str) -> dict[str, Any]:
    if decision in PERMISSION_MAP:
        return _permission_response(PERMISSION_MAP[decision], reasoning)
    if decision == "modify":
        overrides = modifications.get("parameter_overrides")
        if overrides is not None and event_name == "preToolUse":
            return _permission_response("allow", reasoning, updated_input=overrides)
        return _permission_response("deny",
                                     f"MODIFY substituted to DENY: {reasoning}")
    return {}


def _translate_post_tool(decision: str, reasoning: str,
                          modifications: dict, event_name: str) -> dict[str, Any]:
    if decision == "modify":
        if event_name == "afterMCPExecution":
            updated = modifications.get("modified_content")
            if updated is not None:
                return _post_tool_response(updated_mcp_tool_output=str(updated))
        return _post_tool_response(additional_context=f"MODIFY received: {reasoning}")
    if reasoning:
        return _post_tool_response(additional_context=reasoning)
    return {}


def _translate_before_submit_prompt(decision: str, reasoning: str,
                                     modifications: dict,
                                     event_name: str) -> dict[str, Any]:
    """Returns internal markers (__exit_code, _reasoning) consumed by main()."""
    return {"__exit_code": 2 if decision == "deny" else 0,
            "_reasoning": reasoning if decision == "deny" else None}


def translate_response(acs_response: dict[str, Any], event_name: str) -> dict[str, Any]:
    result = acs_response.get("result", {})
    decision = (result.get("decision") or "").lower()
    reasoning = result.get("reasoning", "")
    modifications = result.get("modifications", {})

    # Unknown disposition under fail-closed → emit a deny in the hook's shape.
    if decision not in KNOWN_DECISIONS and DEFAULT_DENY:
        reason = f"unknown Guardian disposition '{decision}' (default-deny)"
        if event_name in PERMISSION_EVENTS:
            return _permission_response("deny", reason)
        if event_name == "beforeSubmitPrompt":
            return {"__exit_code": 2, "_reasoning": reason}

    if event_name in PERMISSION_EVENTS:
        return _translate_permission(decision, reasoning, modifications, event_name)
    if event_name in POST_TOOL_EVENTS:
        return _translate_post_tool(decision, reasoning, modifications, event_name)
    if event_name == "beforeSubmitPrompt":
        return _translate_before_submit_prompt(decision, reasoning, modifications, event_name)

    # subagentStop is dropped from HOOK_MAP entirely (see comment on HOOK_MAP);
    # other events (sessionStart, sessionEnd, stop, subagentStart, preCompact,
    # afterAgentResponse, afterAgentThought) are observational with no
    # response shape — empty dict skips stdout emission.
    return {}


# ─── Main flow ──────────────────────────────────────────────────────────────

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
        return _fail(event_name, cause="invalid_stdin_json")

    if event_name not in HOOK_MAP:
        return 0

    _maybe_handshake(event)

    request = None
    try:
        request = build_request(event_name, event)
        if not request:
            sys.stderr.write(f"acs-adapter: could not build request for {event_name}\n")
            return _fail(event_name, _session_id(event), cause="adapter_build_failed")
        # Track this step in session state so subsequent subagentStart /
        # preCompact events can cite a real parent_step_id / entries_to_compact.
        # Done before call_guardian so even a failed Guardian call leaves
        # the step recorded for audit.
        try:
            sid_for_state = _session_id(event)
            rid_for_state = request.get("params", {}).get("request_id")
            if sid_for_state and rid_for_state:
                record_step(sid_for_state, rid_for_state, workspace=_workspace(event))
        except Exception:  # noqa: BLE001
            pass
        response = call_guardian(request)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return _fail(event_name, _session_id(event),
                     cause="transport_failure",
                     request_id=(request or {}).get("params", {}).get("request_id"),
                     method=(request or {}).get("method"),
                     error=str(e))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(event_name, _session_id(event),
                     cause="adapter_exception", error=str(e))

    # Guardian responded — was it a result or a JSON-RPC error?
    if "error" in response:
        err = response.get("error") or {}
        code = err.get("code")
        cause = guardian_error_cause(code)
        sys.stderr.write(
            f"acs-adapter: Guardian returned JSON-RPC error "
            f"{code} ({cause}): {err.get('message','')}\n")
        return _fail(event_name, _session_id(event),
                     cause=cause,
                     error_code=code,
                     error_message=err.get("message"),
                     request_id=(request or {}).get("params", {}).get("request_id"),
                     method=(request or {}).get("method"))

    if not verify_signature(response, session_id=_session_id(event)):
        sys.stderr.write("acs-adapter: response signature invalid\n")
        return _fail(event_name, _session_id(event),
                     cause="response_signature_invalid")

    out = translate_response(response, event_name)

    if event_name == "beforeSubmitPrompt":
        exit_code = out.pop("__exit_code", 0)
        reasoning = out.pop("_reasoning", None)
        if reasoning:
            sys.stderr.write(f"acs-adapter: blocking prompt: {reasoning}\n")
        # Cursor with `failClosed: true` treats "exit 0 + empty stdout"
        # as a hook FAILURE (since the hook produced no decision), not
        # as an allow. Always emit at minimum `{}` on the allow path so
        # Cursor sees a real response. On deny we still use exit code 2;
        # stdout is ignored for that path.
        if exit_code == 0:
            sys.stdout.write("{}\n")
        return exit_code

    _emit(out)
    return 0


def _fail(event_name: str = "", session_id: str | None = None, *,
          cause: str = "unknown", **audit_extras) -> int:
    """Apply the deployment's fail posture and record an audit event per §6.4.

    `cause` distinguishes the failure mode (transport_failure,
    signature_invalid_response, malformed_envelope_response, etc.)
    independently of the posture. Disposition (fail_open_bypass /
    decision_failure_fail_closed) is determined by ACS_DEFAULT_DENY;
    cause tells operators what actually went wrong so a malformed
    envelope (client bug) doesn't get confused with an unreachable
    Guardian (ops issue).
    """
    if DEFAULT_DENY:
        msg = f"ACS adapter: decision-failure ({cause})"
        if event_name in PERMISSION_EVENTS:
            _emit(_permission_response("deny", msg))
            audit_event("decision_failure_fail_closed",
                        cause=cause, event=event_name, session_id=session_id, **audit_extras)
            return 0
        if event_name == "beforeSubmitPrompt":
            sys.stderr.write(f"acs-adapter: prompt blocked ({cause})\n")
            audit_event("decision_failure_fail_closed",
                        cause=cause, event=event_name, session_id=session_id, **audit_extras)
            return 2
        audit_event("decision_failure_fail_closed",
                    cause=cause, event=event_name, session_id=session_id, **audit_extras)
        return 0

    audit_event("fail_open_bypass",
                cause=cause, event=event_name, session_id=session_id, **audit_extras)
    return 0


if __name__ == "__main__":
    sys.exit(main())
