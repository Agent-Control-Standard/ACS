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
    of the last step_id. When NO prior step is recorded, parent_step_id
    is the spawn event's own request_id (the spawn is the first observed
    parent step) with a `subagent_start_parent_step_unknown` audit event
    — never the session id masquerading as a step id. The fourth field,
    `intent_derivation`, is hardcoded to `derived_from_parent` (the
    defensible default for IDE-spawned subagents).
  - `preCompact` — both required fields are real: `entries_to_compact` is
    the list of step_ids the adapter has observed in this session;
    `triggered_by` comes from Cursor's `trigger` field.
  - `subagentStop` — NOT forwarded. `final_chain_hash` is genuinely
    unknowable (Cursor maintains no chain); better to omit than
    fabricate. The field is now optional for chain-less frameworks
    (PR #21), so honest wiring is possible — tracked for the rebase.

See the README per-hook honesty table for the full mapping.

Usage in hooks.json:
  { "command": "python3 /path/to/acs_adapter.py preToolUse" }

Environment variables (same defaults / semantics as the Claude Code adapter):
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    "1" = fail-closed. Default "0" (spec default per §6.4).
                      Cursor also honors per-hook `failClosed: true` in hooks.json.
                      The ServerHello's `on_decision_failure` also applies
                      (most-restrictive-wins). Guardian REFUSALS
                      (SIGNATURE_INVALID, REPLAY_DETECTED, malformed /
                      oversized envelope) always fail closed regardless of
                      posture — every refusal is attacker-reachable.
  ACS_HMAC_SECRET     Shared secret for HMAC-SHA256 signing per §10 (or
                      ACS_HMAC_SECRET_FILE, preferred). Unset = no signing
                      (local dev, loud audit event).
  ACS_AGENT_ID        Explicit agent_id; defaults to cursor:<sha8(workspace)>.
  ACS_HANDSHAKE       "0" disables handshake. Default "1".
  ACS_AUDIT_FILE      Append every ACS_AUDIT event to this file (0600) in
                      addition to stderr.
  ACS_DISABLED        "1" = incident kill switch: exit immediately, no
                      Guardian traffic, no output (one stderr line).
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
    MAX_REQUEST_BODY_BYTES,
    audit_event,
    coerce_uuid,
    ensure_session_handshake,
    guardian_error_cause,
    is_guardian_refusal,
    iso8601_now,
    load_session_state,
    record_step,
    response_matches_request,
    save_session_state,
    sign_envelope,
    validate_guardian_url,
    verify_signature,
)


class RequestTooLargeError(Exception):
    """Serialized envelope exceeds the Guardian's body cap. Checked
    adapter-side BEFORE the POST — an oversized envelope is attacker-
    constructable and its HTTP 413 / mid-read reset previously fell to
    the fail-open posture as transport_failure (PR #22 second review)."""


class GuardianHTTPRefusalError(Exception):
    """Guardian answered non-2xx: alive and refusing at the HTTP layer.
    urllib raises HTTPError before the JSON-RPC error body is parsed,
    so this was bucketed as transport_failure → fail-open."""

    def __init__(self, status: int, jsonrpc_error: dict | None):
        self.status = status
        self.jsonrpc_error = jsonrpc_error or {}
        super().__init__(f"HTTP {status}")


# Version stamp: distribution is copy-paste, so a defect is only scopeable
# if adopters can answer "what version do you run?" (PR #22 review).
# Bump on EVERY behavior change to this file. Carried in request metadata
# and printed by --version.
ADAPTER_VERSION = "0.1.1"

GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
HANDSHAKE_ENABLED = os.environ.get("ACS_HANDSHAKE", "1") == "1"

# Effective fail posture = most-restrictive of the local env var and the
# Guardian's negotiated ServerHello `on_decision_failure` (§6.4). Updated
# once per invocation in main(). See the Claude Code adapter for the full
# rationale (PR #22 review: the ServerHello was fetched and never read).
_SERVER_DENY = False


def _effective_default_deny() -> bool:
    return DEFAULT_DENY or _SERVER_DENY


# ─── Hook taxonomy ──────────────────────────────────────────────────────────

# Cursor hook event -> ACS step method.
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

# Cursor events we deliberately do NOT map, with the reason. An event
# outside HOOK_MAP and outside this set gets an `unmapped_hook_event`
# audit line, so a renamed upstream hook shows up as an ungoverned
# session instead of a quiet one (PR #22 review).
KNOWN_UNMAPPED: dict[str, str] = {
    # `final_chain_hash` (64-hex SHA-256 of the subagent's ContextEntry
    # chain) is genuinely unknowable because Cursor maintains no chain.
    # Emitting a fabricated hash would be schema-valid but semantically
    # meaningless. PR #21 makes the field optional; wiring subagentStop
    # honestly becomes possible after it lands and is tracked for the
    # rebase. The Cursor README per-hook honesty table documents the gap.
    "subagentStop": "final_chain_hash unknowable (no chain on Cursor side)",
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
    parent_step_id = st.get("last_step_id")
    if not parent_step_id:
        # No prior step recorded (spawn is the first event the adapter
        # sees in this session, or the session-state cache was cleared).
        # Previously this fell back to the session_id — which is NOT a
        # step id; the schema says parent_step_id is the step that
        # triggered the spawn, and a session id masquerading as one is
        # fabricated lineage (PR #22 fourth review). The honest value is
        # self-referential: the spawn event itself IS the first parent
        # step this adapter observed, so build_request patches in this
        # envelope's own request_id (sentinel None here) and the
        # degraded lineage is audited.
        audit_event("subagent_start_parent_step_unknown",
                    session_id=sid,
                    detail="no prior step recorded; parent_step_id set "
                           "to the spawn event's own request_id")
        parent_step_id = None
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
        "adapter_version": ADAPTER_VERSION,
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

    payload = build_payload(event_name, event)
    # subagentStart with no recorded prior step: the spawn event itself
    # is the first observed parent step, so its own request_id is the
    # honest parent_step_id (see _payload_subagent_start).
    if method == "steps/subagentStart" and payload.get("parent_step_id") is None:
        payload["parent_step_id"] = request_id

    envelope = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": request_id,
            "timestamp": iso8601_now(),
            "metadata": metadata,
            "payload": payload,
        },
    }
    sign_envelope(envelope, session_id=session_id)
    return envelope


def _maybe_handshake(event: dict[str, Any]) -> dict | None:
    """Called on every hook event. Idempotent per session via disk
    cache — only the first event of a session actually POSTs
    handshake/hello. Returns the negotiated ServerHello (cached or
    fresh) or None. See ensure_session_handshake's docstring."""
    if not HANDSHAKE_ENABLED:
        return None
    sid = _session_id(event)
    if not sid:
        return None
    return ensure_session_handshake(
        guardian_url=GUARDIAN_URL,
        session_id=sid,
        agent_id=_agent_id(event),
        platform="cursor",
        methods_implemented=list(HOOK_MAP.values()),
    )


def call_guardian(request: dict[str, Any]) -> dict[str, Any]:
    validate_guardian_url(GUARDIAN_URL)  # SSRF: refuse file://, ftp://, etc.
    body = json.dumps(request).encode("utf-8")
    if len(body) > MAX_REQUEST_BODY_BYTES:
        raise RequestTooLargeError(len(body))
    req = urllib.request.Request(
        GUARDIAN_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        parsed = None
        try:
            parsed = json.loads(e.read().decode("utf-8")).get("error")
        except Exception:  # noqa: BLE001
            pass
        raise GuardianHTTPRefusalError(e.code, parsed) from e


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

    # Unknown or missing disposition: ALWAYS audited — the fail-open
    # branch is the shipped default and §6.4 says every step that
    # proceeds without a decision MUST be recorded (PR #22 review).
    if decision not in KNOWN_DECISIONS:
        audit_event("unknown_disposition",
                    disposition=decision or "(missing)", event=event_name,
                    posture="deny" if _effective_default_deny() else "proceed")
        if _effective_default_deny():
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
    global _SERVER_DENY
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(f"acs-adapter (cursor) {ADAPTER_VERSION}")
        return 0
    if os.environ.get("ACS_DISABLED") == "1":
        # Incident kill switch: no Guardian traffic, no output. One
        # stderr line so the bypass is at least visible in debug logs.
        sys.stderr.write("acs-adapter: ACS_DISABLED=1 — hook bypassed\n")
        return 0

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
        if event_name not in KNOWN_UNMAPPED:
            # Likely an upstream rename or an event wired in hooks.json
            # that this adapter doesn't know. Going quiet would make an
            # ungoverned session look like a quiet one (PR #22 review).
            audit_event("unmapped_hook_event", event=event_name,
                        session_id=_session_id(event))
        return 0

    server_hello = _maybe_handshake(event)
    if server_hello and server_hello.get("on_decision_failure") == "deny":
        _SERVER_DENY = True

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
    except RequestTooLargeError as e:
        sys.stderr.write(f"acs-adapter: envelope exceeds body cap: {e}\n")
        return _force_deny(event_name, _session_id(event),
                           cause="request_exceeds_max_payload",
                           body_bytes=e.args[0],
                           method=(request or {}).get("method"))
    except GuardianHTTPRefusalError as e:
        code = e.jsonrpc_error.get("code")
        cause = (guardian_error_cause(code) if code is not None
                 else f"http_{e.status}_refusal")
        sys.stderr.write(
            f"acs-adapter: Guardian refused at HTTP layer "
            f"({e.status}, {cause})\n")
        return _force_deny(event_name, _session_id(event),
                           cause=cause, http_status=e.status,
                           error_code=code,
                           error_message=e.jsonrpc_error.get("message"),
                           method=(request or {}).get("method"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
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

    # Bind the response to THIS request before anything else — the HMAC
    # proves origin, not correspondence; a captured signed ALLOW for a
    # benign call verifies fine replayed against a destructive one
    # (PR #22 review). Mis-bound responses always fail closed.
    if not response_matches_request(request, response):
        sys.stderr.write("acs-adapter: response not bound to request\n")
        return _force_deny(event_name, _session_id(event),
                           cause="response_binding_mismatch")

    # Guardian responded — was it a result or a JSON-RPC error?
    # Refusal codes mean the Guardian is ALIVE and REFUSED this envelope;
    # each is attacker-reachable, so they fail closed regardless of
    # posture (PR #22 review). Non-refusal errors follow §6.4.
    if "error" in response:
        # Error responses are signed too — a spoofable unsigned error
        # under a fail-open posture is an allow (PR #22 third review).
        if not verify_signature(response, session_id=_session_id(event)):
            sys.stderr.write("acs-adapter: error response signature invalid\n")
            claimed = response.get("error") or {}
            return _force_deny(event_name, _session_id(event),
                               cause="error_signature_invalid",
                               # UNVERIFIED — for triage only.
                               claimed_error_code=claimed.get("code"),
                               claimed_cause=guardian_error_cause(claimed.get("code")))
        err = response.get("error") or {}
        code = err.get("code")
        cause = guardian_error_cause(code)
        sys.stderr.write(
            f"acs-adapter: Guardian returned JSON-RPC error "
            f"{code} ({cause}): {err.get('message','')}\n")
        common = dict(cause=cause, error_code=code,
                      error_message=err.get("message"),
                      request_id=(request or {}).get("params", {}).get("request_id"),
                      method=(request or {}).get("method"))
        if is_guardian_refusal(code):
            return _force_deny(event_name, _session_id(event), **common)
        return _fail(event_name, _session_id(event), **common)

    # An invalid signature on a well-formed response is spoofing or key
    # mismatch — fail closed, never posture.
    if not verify_signature(response, session_id=_session_id(event)):
        sys.stderr.write("acs-adapter: response signature invalid\n")
        return _force_deny(event_name, _session_id(event),
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
    if _effective_default_deny():
        return _deny_with_audit("decision_failure_fail_closed",
                                event_name, session_id, cause, audit_extras)

    audit_event("fail_open_bypass",
                cause=cause, event=event_name, session_id=session_id, **audit_extras)
    return 0


def _force_deny(event_name: str = "", session_id: str | None = None, *,
                cause: str = "unknown", **audit_extras) -> int:
    """Fail closed REGARDLESS of posture.

    For attacker-shaped conditions where 'proceed' is a bypass primitive:
    Guardian refusals (GUARDIAN_REFUSAL_CODES), response↔request binding
    mismatches, and invalid response signatures (PR #22 review)."""
    return _deny_with_audit("guardian_refusal_fail_closed",
                            event_name, session_id, cause, audit_extras)


def _deny_with_audit(audit_type: str, event_name: str,
                     session_id: str | None, cause: str,
                     audit_extras: dict) -> int:
    """Emit a deny in the event's native shape + one audit event."""
    audit_event(audit_type,
                cause=cause, event=event_name, session_id=session_id,
                **audit_extras)
    if event_name in PERMISSION_EVENTS:
        _emit(_permission_response(
            "deny", f"ACS adapter: decision-failure ({cause})"))
        return 0
    if event_name == "beforeSubmitPrompt":
        sys.stderr.write(f"acs-adapter: prompt blocked ({cause})\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
