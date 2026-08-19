#!/usr/bin/env python3
"""
ACS adapter for Claude Code hooks.

Translates a Claude Code hook event (read from stdin as JSON) into an
ACS JSON-RPC request, signs it (HMAC-SHA256 baseline per Specification
§10 when ACS_HMAC_SECRET is set), sends it to a Guardian, and
translates the ACS response back to Claude Code's expected output.

Wire-format ground truth: Agent-Control-Standard/ACS specification/v0.1.0/

Environment variables:
  ACS_GUARDIAN_URL    Guardian endpoint (default: http://127.0.0.1:8787/acs)
  ACS_DEFAULT_DENY    "1" = fail-closed on adapter error or unknown
                      Guardian disposition. Default: "0" (spec default
                      per §6.4 is fail-open with audit event). Switch
                      to "1" for production deployments that prefer
                      fail-closed availability tradeoff. The negotiated
                      ServerHello's `on_decision_failure` also applies:
                      the adapter fails closed when EITHER this env var
                      or the Guardian's declared posture says deny
                      (most-restrictive-wins).
                      Guardian REFUSALS (SIGNATURE_INVALID, REPLAY_DETECTED,
                      oversized/malformed envelope, …) always fail closed
                      regardless of posture — a refusal is an alive
                      Guardian rejecting the envelope, and every refusal
                      is attacker-reachable (see GUARDIAN_REFUSAL_CODES).
  ACS_HMAC_SECRET     Shared secret for baseline HMAC-SHA256 envelope
                      signing per §10 (or ACS_HMAC_SECRET_FILE, preferred
                      for production). If unset, requests are unsigned
                      (local-dev mode, loud audit event). ACS-Core
                      conformance requires one of these to be set.
  ACS_AGENT_ID        Explicit agent_id for metadata. If unset, derived
                      from cwd as `claude-code:<sha8(cwd)>`.
  ACS_HANDSHAKE       "0" disables the handshake/hello call on first
                      use. Default "1". Handshake result is cached
                      per-session in ~/.cache/acs-adapter-handshake/.
  ACS_AUDIT_FILE      Append every ACS_AUDIT event to this file (0600)
                      in addition to stderr, so the §6.4 audit half of
                      the fail-open trade lands somewhere durable.
  ACS_DISABLED        "1" = incident kill switch: the adapter exits
                      immediately with no Guardian traffic and no output
                      (one stderr line). Use when a degraded Guardian is
                      stalling every hook and you need the agent usable
                      NOW; re-enable by unsetting. Documented incident
                      procedure — faster and more reversible than
                      hand-editing settings.json per machine.
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


# Bootstrap shared helpers from sibling adapters/_common/
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
    response_matches_request,
    sign_envelope,
    validate_guardian_url,
    verify_signature,
)


class RequestTooLargeError(Exception):
    """The serialized envelope exceeds the Guardian's body cap.

    Checked adapter-side BEFORE the POST: an oversized envelope is
    attacker-constructable (a 2 MiB tool argument), and depending on
    transport timing the Guardian's HTTP 413 can surface as HTTPError
    or a mid-read connection reset — the latter is indistinguishable
    from a transport failure and previously fell to the fail-open
    posture (PR #22 second review). Failing closed before the wire
    removes the ambiguity."""


class GuardianHTTPRefusalError(Exception):
    """The Guardian answered with a non-2xx HTTP status — alive and
    refusing at the HTTP layer (413 oversized, 400 bad frame). urllib
    raises HTTPError for these before the JSON-RPC error body is ever
    parsed, so without this classification an HTTP-level refusal was
    bucketed as transport_failure and fell to the fail-open posture
    (PR #22 second review)."""

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
# Guardian's negotiated ServerHello `on_decision_failure` (§6.4 says the
# posture is declared in the handshake — previously the ServerHello was
# fetched, cached, and never read, so the Guardian's declared posture had
# no effect; PR #22 review). Updated once per invocation in main().
_SERVER_DENY = False


def _effective_default_deny() -> bool:
    return DEFAULT_DENY or _SERVER_DENY


# ─── Hook taxonomy ──────────────────────────────────────────────────────────

HOOK_MAP: dict[str, str] = {
    "SessionStart":     "steps/sessionStart",
    "SessionEnd":       "steps/sessionEnd",
    "UserPromptSubmit": "steps/userMessage",
    "PreToolUse":       "steps/toolCallRequest",
    "PostToolUse":      "steps/toolCallResult",
    "Notification":     "steps/agentResponse",
    "Stop":             "steps/sessionEnd",
    "SubagentStop":     "steps/subagentStop",
}

# Claude Code events we deliberately do NOT map, with the reason. An
# event outside HOOK_MAP and outside this set gets an
# `unmapped_hook_event` audit line so a renamed upstream hook shows up
# as an ungoverned session instead of a quiet one (PR #22 review).
KNOWN_UNMAPPED: dict[str, str] = {
    # steps/preCompact requires entries_to_compact (minItems 1) — the
    # step_ids being folded into the summary. Claude Code's PreCompact
    # event carries no entry list, so an honest payload can't be built;
    # emitting an empty or fabricated list would defeat the hook's
    # provenance-laundering purpose. Documented Guardian visibility gap.
    "PreCompact": "platform exposes no entry list for steps/preCompact",
}

# Hooks whose deny shape is {"decision": "block", "reason": "..."}
# (i.e., everything except PreToolUse, which uses hookSpecificOutput.permissionDecision).
BLOCK_RESPONSE_HOOKS = frozenset({
    "PostToolUse", "UserPromptSubmit", "Stop", "SubagentStop",
})

SESSION_END_REASON_MAP: dict[str, str] = {
    "clear":             "completed",
    "logout":            "abandoned",
    "prompt_input_exit": "abandoned",
    "other":             "completed",
}

# Claude Code's permissionDecision accepts allow | deny | ask — there is
# no native "defer". DEFER substitutes to deny, matching the spec default
# `timeout_decision: deny` (§6): an unresolvable verdict on the one hook
# that gates execution must not pass through as an invalid value the
# framework ignores (PR #22 review). The substitution is audited.
PRETOOL_PERMISSION_MAP: dict[str, str] = {
    "allow": "allow", "deny": "deny", "ask": "ask",
}

KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


# ─── Response writers — one definition each, used everywhere ──────────────

def _emit(payload: dict[str, Any]) -> None:
    """Single point where the adapter writes to stdout. Idempotent if
    called with empty dict."""
    if not payload:
        return
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def _pretool_response(decision: str, reason: str = "",
                       updated_input: dict | None = None) -> dict[str, Any]:
    """Build Claude Code's PreToolUse response shape."""
    hso: dict[str, Any] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
    }
    if reason:
        hso["permissionDecisionReason"] = reason
    if updated_input is not None:
        hso["updatedInput"] = updated_input
    return {"hookSpecificOutput": hso}


def _block_response(reason: str, hook_event: str | None = None) -> dict[str, Any]:
    """Build Claude Code's generic block shape used by PostToolUse,
    UserPromptSubmit, Stop, SubagentStop, PreCompact."""
    out: dict[str, Any] = {"decision": "block", "reason": reason}
    if hook_event:
        out["hookSpecificOutput"] = {"hookEventName": hook_event}
    return out


# ─── Helpers ────────────────────────────────────────────────────────────────

def _agent_id(event: dict[str, Any]) -> str:
    explicit = os.environ.get("ACS_AGENT_ID")
    if explicit:
        return explicit
    cwd = event.get("cwd") or os.environ.get("PWD") or ""
    if cwd:
        return f"claude-code:{hashlib.sha256(cwd.encode()).hexdigest()[:8]}"
    return "claude-code:unknown"


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _tool_use_request_id(tool_use_id: str | None) -> str | None:
    """Deterministic UUID5 from Claude Code's tool_use_id so PostToolUse
    can populate `request_id_ref` (per tool-call-result.json:19-23)
    linking back to its originating PreToolUse request."""
    if not tool_use_id:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"claude-code:tool_use:{tool_use_id}"))


# ─── Payload builders — dispatch table, one function per hook ──────────────
#
# Each function takes the Claude Code event dict and returns the
# hook-payload portion of the ACS envelope (the part that goes under
# `params.payload`). The dispatch table at the bottom maps hook names
# to these functions; build_payload is then a one-line dispatch.

def _payload_pretool_use(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": {"name": event.get("tool_name", "")},
        "arguments": _wrap_arguments(event.get("tool_input") or {}),
    }


def _payload_post_tool_use(event: dict[str, Any]) -> dict[str, Any]:
    tool_response = event.get("tool_response", event.get("tool_output"))
    interrupted = isinstance(tool_response, dict) and tool_response.get("interrupted")
    payload: dict[str, Any] = {
        "tool": {"name": event.get("tool_name", "")},
        "exit_status": "failure" if interrupted else "success",
        "outputs": [{"value": tool_response}] if tool_response is not None else [],
    }
    ref = _tool_use_request_id(event.get("tool_use_id"))
    if ref:
        payload["request_id_ref"] = ref
    if event.get("duration_ms") is not None:
        payload["duration_ms"] = event["duration_ms"]
    return payload


def _payload_user_prompt(event: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "value": event.get("prompt", "")}]}


def _payload_notification(event: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "value": event.get("message", "")}]}


def _payload_session_start(event: dict[str, Any]) -> dict[str, Any]:
    ctx = {k: v for k, v in (
        ("source", event.get("source")),
        ("model", event.get("model")),
        ("transcript_path", event.get("transcript_path"))
    ) if v}
    return {"platform_context": ctx} if ctx else {}


def _payload_session_end(event: dict[str, Any]) -> dict[str, Any]:
    name = event.get("hook_event_name", "")
    raw_reason = event.get("reason") or ("completed" if name == "Stop" else "other")
    return {"reason": SESSION_END_REASON_MAP.get(raw_reason, "completed")}


def _payload_subagent_stop(event: dict[str, Any]) -> dict[str, Any]:
    """steps/subagentStop from Claude Code's SubagentStop event.

    Best-effort mapping, honestly scoped:
      - subagent_session_id: Claude Code doesn't surface the subagent's
        own session id, so we derive a deterministic UUID5 from the most
        specific identifier available (agent transcript path when
        present, else the parent session_id). Deterministic, so repeat
        events for the same subagent map to the same id.
      - outcome: always "completed" — SubagentStop fires on completion
        and the event carries no failure discriminator.
      - final_chain_hash: OMITTED. Claude Code maintains no session
        chain; fabricating an integrity value would corrupt the exact
        artifact the field exists to produce. PR #21 makes the field
        optional for chain-less frameworks (this PR is sequenced after
        it).
    """
    ident = (event.get("agent_transcript_path")
             or event.get("transcript_path")
             or event.get("session_id") or "")
    # Always uuid5-derive (never pass through): when the fallback is the
    # parent session_id, passing it through would make the subagent's id
    # EQUAL its parent's, which corrupts the parent-child relation.
    return {
        "subagent_session_id": str(uuid.uuid5(
            uuid.NAMESPACE_URL, f"claude-code:subagent:{ident}")),
        "outcome": "completed",
    }


_PAYLOAD_BUILDERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "PreToolUse":       _payload_pretool_use,
    "PostToolUse":      _payload_post_tool_use,
    "UserPromptSubmit": _payload_user_prompt,
    "Notification":     _payload_notification,
    "SessionStart":     _payload_session_start,
    "SessionEnd":       _payload_session_end,
    "Stop":             _payload_session_end,
    "SubagentStop":     _payload_subagent_stop,
}


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    builder = _PAYLOAD_BUILDERS.get(event.get("hook_event_name", ""))
    return builder(event) if builder else {}


# ─── Envelope construction ──────────────────────────────────────────────────

def _is_task_spawn(event: dict[str, Any]) -> bool:
    """True when this PreToolUse IS a subagent spawn (the Task tool)."""
    return (event.get("hook_event_name") == "PreToolUse"
            and (event.get("tool_name") or "").lower() == "task")


def _payload_subagent_start(event: dict[str, Any]) -> dict[str, Any]:
    """steps/subagentStart from PreToolUse(tool_name="Task").

    Post-#21, subagentStart is the Core floor's confused-deputy gate for
    subagent-capable clients, and Claude Code IS subagent-capable: the
    Task tool call is the observable spawn boundary. Mapping it to a
    generic toolCallRequest hid the spawn from any Guardian keying
    policy on the subagent hooks (PR #22 fourth review). Every required
    field is real:
      - parent_step_id: the deterministic request_id of this very
        PreToolUse (uuid5 of tool_use_id) — the schema's own example of
        a parent step is "a steps/toolCallRequest for a delegation tool".
      - subagent_session_id: deterministic uuid5 of the tool_use_id
        under a distinct namespace (Claude Code assigns the child's real
        session id only after the spawn; this id is stable for audit
        correlation and never collides with the parent's).
      - parent_session_id: the actual session_id.
      - intent_derivation: "derived_from_parent" — the Task prompt is
        authored by the parent agent, so the child's intent derives from
        the parent's. Never "fresh" (that claims authority NOT derived
        from the parent and is deny-by-default at the Guardian).
    """
    tool_use_id = event.get("tool_use_id") or ""
    tool_input = event.get("tool_input") or {}
    if tool_use_id:
        subagent_session_id = str(uuid.uuid5(
            uuid.NAMESPACE_URL, f"claude-code:subagent:{tool_use_id}"))
        parent_step_id = _tool_use_request_id(tool_use_id)
    else:
        # No tool_use_id on the event. Previously this minted a random
        # uuid4 as parent_step_id (invented lineage) and a uuid5 of the
        # EMPTY STRING as subagent_session_id (every id-less spawn in
        # every session mapped to the same stable id — PR #22 fifth
        # review). Honest handling mirrors the Cursor adapter: both ids
        # are patched in build_request from the envelope's own
        # request_id (the spawn event IS the delegation step), and the
        # degraded identity is audited.
        audit_event("subagent_spawn_id_unavailable",
                    session_id=event.get("session_id"),
                    detail="PreToolUse(Task) carried no tool_use_id; "
                           "subagent_session_id and parent_step_id "
                           "derive from the spawn envelope's request_id")
        subagent_session_id = None
        parent_step_id = None
    payload: dict[str, Any] = {
        "subagent_session_id": subagent_session_id,
        "parent_session_id": event.get("session_id", ""),
        "parent_step_id": parent_step_id,
        "intent_derivation": "derived_from_parent",
    }
    descriptor: dict[str, Any] = {}
    if tool_input.get("subagent_type"):
        descriptor["agent_name"] = str(tool_input["subagent_type"])
    if descriptor:
        payload["subagent_descriptor"] = descriptor
    return payload


def build_request(event: dict[str, Any]) -> dict[str, Any]:
    method = HOOK_MAP.get(event.get("hook_event_name", ""))
    if method is None:
        return {}

    session_id = event.get("session_id")
    if not session_id:
        return {}

    # The Task tool is Claude Code's subagent spawn — route it to the
    # dedicated confused-deputy gate instead of the generic tool hook.
    task_spawn = _is_task_spawn(event)
    if task_spawn:
        method = "steps/subagentStart"

    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": session_id,
        "platform": "claude-code",
        "adapter_version": ADAPTER_VERSION,
    }
    for k in ("cwd", "transcript_path", "permission_mode"):
        if event.get(k):
            metadata[k] = event[k]

    # For PreToolUse (including the Task→subagentStart remap), pin
    # request_id to a deterministic UUID derived from tool_use_id so the
    # matching PostToolUse can reference it.
    request_id = (_tool_use_request_id(event.get("tool_use_id"))
                  if event.get("hook_event_name") == "PreToolUse"
                  else None) or str(uuid.uuid4())

    payload = (_payload_subagent_start(event) if task_spawn
               else build_payload(event))
    if task_spawn:
        # No tool_use_id case: the spawn event's own request_id is the
        # honest identity source — it IS the delegation step, and the
        # derived subagent id is unique per spawn instead of a stable
        # uuid5 of the empty string (see _payload_subagent_start).
        if payload.get("parent_step_id") is None:
            payload["parent_step_id"] = request_id
        if payload.get("subagent_session_id") is None:
            payload["subagent_session_id"] = str(uuid.uuid5(
                uuid.NAMESPACE_URL, f"claude-code:subagent:{request_id}"))

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
    """Called on every hook event. Returns the negotiated ServerHello
    (cached or fresh) or None.

    Looks like 'handshake every event', but `ensure_session_handshake`
    is idempotent: the FIRST event of a session_id triggers a real
    handshake/hello POST and writes the negotiated ServerHello to
    ~/.cache/acs-adapter-handshake/. Every subsequent event for the
    same session_id reads that file and returns without a network call.
    """
    if not HANDSHAKE_ENABLED:
        return None
    session_id = event.get("session_id")
    if not session_id:
        return None
    return ensure_session_handshake(
        guardian_url=GUARDIAN_URL,
        session_id=session_id,
        agent_id=_agent_id(event),
        platform="claude-code",
        # steps/subagentStart is emitted via the PreToolUse(Task) remap,
        # so it is not a HOOK_MAP value — advertise it explicitly
        # (PR #22 fourth review: the handshake previously undersold the
        # implemented surface).
        methods_implemented=list(HOOK_MAP.values()) + ["steps/subagentStart"],
    )


def call_guardian(request: dict[str, Any]) -> dict[str, Any]:
    validate_guardian_url(GUARDIAN_URL)  # SSRF: refuse file://, ftp://, etc.
    body = json.dumps(request).encode("utf-8")
    if len(body) > MAX_REQUEST_BODY_BYTES:
        # Fail closed BEFORE the wire — see RequestTooLargeError.
        raise RequestTooLargeError(len(body))
    req = urllib.request.Request(
        GUARDIAN_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Non-2xx = alive Guardian refusing at the HTTP layer. Recover
        # the JSON-RPC error body when there is one so the audit event
        # carries the specific code.
        parsed = None
        try:
            parsed = json.loads(e.read().decode("utf-8")).get("error")
        except Exception:  # noqa: BLE001
            pass
        raise GuardianHTTPRefusalError(e.code, parsed) from e


# ─── Response translation — dispatch table, one function per hook ─────────

def _translate_pretool(decision: str, reasoning: str,
                        modifications: dict) -> dict[str, Any]:
    if decision in PRETOOL_PERMISSION_MAP:
        return _pretool_response(PRETOOL_PERMISSION_MAP[decision], reasoning)
    if decision == "defer":
        # No native defer in permissionDecision; spec default
        # timeout_decision is deny (§6). Audited so substitution rate
        # is machine-visible.
        audit_event("defer_substituted_deny", hook="PreToolUse")
        return _pretool_response(
            "deny", f"DEFER substituted to DENY (no native defer): {reasoning}")
    if decision == "modify":
        overrides = modifications.get("parameter_overrides")
        if overrides is not None:
            return _pretool_response("allow", reasoning, updated_input=overrides)
        return _pretool_response(
            "deny",
            f"MODIFY substituted to DENY (no parameter_overrides): {reasoning}",
        )
    return {}


def _translate_posttool(decision: str, reasoning: str,
                         modifications: dict) -> dict[str, Any]:
    if decision == "deny":
        return _block_response(reasoning or "blocked by Guardian", "PostToolUse")
    if decision == "modify":
        updated = modifications.get("modified_content")
        if updated is not None:
            hso = {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": str(updated),
            }
            if reasoning:
                hso["additionalContext"] = reasoning
            return {"hookSpecificOutput": hso}
        return _block_response(
            f"MODIFY substituted to DENY (no modified_content): {reasoning}")
    if decision in ("ask", "defer"):
        return _block_response(
            f"{decision} on post-tool not supported by Claude Code: {reasoning}")
    return {}


def _translate_user_prompt(decision: str, reasoning: str,
                            modifications: dict) -> dict[str, Any]:
    if decision == "deny":
        return _block_response(reasoning or "blocked by Guardian")
    if decision in ("ask", "defer"):
        return _block_response(f"{decision} on user prompt: {reasoning}")
    return {}


def _translate_session_stop(decision: str, reasoning: str,
                             modifications: dict) -> dict[str, Any]:
    """Stop / SubagentStop — only deny matters; allow is the default."""
    if decision == "deny":
        return _block_response(reasoning or "blocked by Guardian")
    return {}


_TRANSLATORS: dict[str, Callable[[str, str, dict], dict[str, Any]]] = {
    "PreToolUse":       _translate_pretool,
    "PostToolUse":      _translate_posttool,
    "UserPromptSubmit": _translate_user_prompt,
    "Stop":             _translate_session_stop,
    "SubagentStop":     _translate_session_stop,
}


def translate_response(acs_response: dict[str, Any], hook_event: str) -> dict[str, Any]:
    result = acs_response.get("result", {})
    decision = (result.get("decision") or "").lower()
    reasoning = result.get("reasoning", "")
    modifications = result.get("modifications", {})

    # Unknown or missing disposition: ALWAYS audited — the fail-open
    # branch is the shipped default and §6.4 says every step that
    # proceeds without a decision MUST be recorded (PR #22 review:
    # previously the fail-open path here allowed with no audit event).
    if decision not in KNOWN_DECISIONS:
        audit_event("unknown_disposition",
                    disposition=decision or "(missing)", hook=hook_event,
                    posture="deny" if _effective_default_deny() else "proceed")
        if _effective_default_deny():
            reason = f"unknown Guardian disposition '{decision}' (default-deny)"
            if hook_event == "PreToolUse":
                return _pretool_response("deny", reason)
            if hook_event in BLOCK_RESPONSE_HOOKS:
                return _block_response(reason)

    translator = _TRANSLATORS.get(hook_event)
    if translator:
        return translator(decision, reasoning, modifications)

    # Informational hooks (SessionStart, SessionEnd, Notification) —
    # surface additional_context if the Guardian provided any, else empty.
    additional = result.get("additional_context")
    if additional:
        return {"hookSpecificOutput": {
            "hookEventName": hook_event,
            "additionalContext": str(additional),
        }}
    return {}


# ─── Main flow ──────────────────────────────────────────────────────────────

def main() -> int:
    global _SERVER_DENY
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(f"acs-adapter (claude-code) {ADAPTER_VERSION}")
        return 0
    if os.environ.get("ACS_DISABLED") == "1":
        # Incident kill switch: no Guardian traffic, no output. One
        # stderr line so the bypass is at least visible in debug logs.
        sys.stderr.write("acs-adapter: ACS_DISABLED=1 — hook bypassed\n")
        return 0

    raw = sys.stdin.read().strip()
    if not raw:
        return 0
    try:
        event = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"acs-adapter: invalid JSON on stdin: {e}\n")
        return _fail(cause="invalid_stdin_json")

    hook_name = event.get("hook_event_name", "")
    if hook_name not in HOOK_MAP:
        if hook_name not in KNOWN_UNMAPPED:
            # A hook we don't recognize — most likely an upstream rename
            # or a new event wired in settings.json. Going quiet here
            # makes an ungoverned session look like a quiet one
            # (PR #22 review), so say so on the audit stream.
            audit_event("unmapped_hook_event", hook=hook_name,
                        session_id=event.get("session_id"))
        return 0

    # Handshake on first call of a session (cached after). Best-effort:
    # a failed handshake follows the deployment's startup posture (§4.1).
    # The negotiated posture participates in the effective fail posture
    # (most-restrictive-wins with ACS_DEFAULT_DENY).
    server_hello = _maybe_handshake(event)
    if server_hello and server_hello.get("on_decision_failure") == "deny":
        _SERVER_DENY = True

    request = None
    try:
        request = build_request(event)
        if not request:
            sys.stderr.write(f"acs-adapter: could not build request for {hook_name}\n")
            return _fail(hook_name, event.get("session_id"),
                         cause="adapter_build_failed")
        response = call_guardian(request)
    except RequestTooLargeError as e:
        # Attacker-constructable; always fail closed (PR #22 second review).
        sys.stderr.write(f"acs-adapter: envelope exceeds body cap: {e}\n")
        return _force_deny(hook_name, event.get("session_id"),
                           cause="request_exceeds_max_payload",
                           body_bytes=e.args[0],
                           method=(request or {}).get("method"))
    except GuardianHTTPRefusalError as e:
        # Alive Guardian, HTTP-layer refusal (413/400) — always fail
        # closed; previously bucketed as transport_failure → fail-open.
        code = e.jsonrpc_error.get("code")
        cause = (guardian_error_cause(code) if code is not None
                 else f"http_{e.status}_refusal")
        sys.stderr.write(
            f"acs-adapter: Guardian refused at HTTP layer "
            f"({e.status}, {cause})\n")
        return _force_deny(hook_name, event.get("session_id"),
                           cause=cause, http_status=e.status,
                           error_code=code,
                           error_message=e.jsonrpc_error.get("message"),
                           method=(request or {}).get("method"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return _fail(hook_name, event.get("session_id"),
                     cause="transport_failure",
                     request_id=(request or {}).get("params", {}).get("request_id"),
                     method=(request or {}).get("method"),
                     error=str(e))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(hook_name, event.get("session_id"),
                     cause="adapter_exception", error=str(e))

    # Bind the response to THIS request before anything else. The
    # per-session HMAC proves the response came from the Guardian, not
    # that it answers this request — a captured signed ALLOW for a
    # benign `ls` verifies fine when replayed against `rm -rf ~/`
    # (PR #22 review). A mis-bound response is attacker-shaped: always
    # fail closed, never posture.
    if not response_matches_request(request, response):
        sys.stderr.write("acs-adapter: response not bound to request\n")
        return _force_deny(hook_name, event.get("session_id"),
                           cause="response_binding_mismatch")

    # Guardian responded — was it a result or a JSON-RPC error?
    # An `error` means the Guardian explicitly rejected this envelope,
    # which is NOT a transport failure. Refusal codes (SIGNATURE_INVALID,
    # REPLAY_DETECTED, malformed/oversized envelope, …) mean the Guardian
    # is ALIVE and REFUSED — every one is attacker-reachable (oversize
    # the body past the Guardian's cap, replay a deterministic
    # request_id, strip the signature), so they fail closed regardless
    # of posture instead of converting into a policy-bypass primitive
    # (PR #22 review). Non-refusal errors follow the §6.4 posture.
    if "error" in response:
        # Error responses are signed too — conformance.md:23's "every
        # request and response" includes errors, because a spoofable
        # unsigned error under a fail-open posture is an allow
        # (PR #22 third review). Unverifiable error → fail closed.
        if not verify_signature(response, session_id=event.get("session_id")):
            sys.stderr.write("acs-adapter: error response signature invalid\n")
            claimed = response.get("error") or {}
            return _force_deny(hook_name, event.get("session_id"),
                               cause="error_signature_invalid",
                               # UNVERIFIED — for triage only; the
                               # disposition (deny) never depends on it.
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
            return _force_deny(hook_name, event.get("session_id"), **common)
        return _fail(hook_name, event.get("session_id"), **common)

    # Response signature check (only relevant when signing is enabled).
    # An invalid signature on a well-formed response is a spoofing
    # attempt or key mismatch — fail closed, never posture.
    if not verify_signature(response, session_id=event.get("session_id")):
        sys.stderr.write("acs-adapter: response signature invalid\n")
        return _force_deny(hook_name, event.get("session_id"),
                           cause="response_signature_invalid")

    _emit(translate_response(response, hook_name))
    return 0


def _fail(hook_name: str = "", session_id: str | None = None, *,
          cause: str = "unknown", **audit_extras) -> int:
    """Apply the deployment's fail posture and record an audit event per §6.4.

    `cause` distinguishes the failure mode (transport_failure,
    signature_invalid_response, malformed_envelope_response, etc.)
    independently of the posture. The audit event's top-level type
    (`fail_open_bypass` or `decision_failure_fail_closed`) is set by
    the effective posture (ACS_DEFAULT_DENY OR the ServerHello's
    on_decision_failure); the `cause` field tells operators what
    actually went wrong so a malformed envelope (client bug) doesn't
    get confused with an unreachable Guardian (ops issue).
    """
    if _effective_default_deny():
        _emit_deny(hook_name, f"ACS adapter: decision-failure ({cause})")
        audit_event("decision_failure_fail_closed",
                    cause=cause, hook=hook_name, session_id=session_id,
                    **audit_extras)
        return 0

    audit_event("fail_open_bypass",
                cause=cause, hook=hook_name, session_id=session_id,
                **audit_extras)
    return 0


def _force_deny(hook_name: str = "", session_id: str | None = None, *,
                cause: str = "unknown", **audit_extras) -> int:
    """Fail closed REGARDLESS of posture.

    For attacker-shaped conditions where 'proceed' is a bypass primitive:
    Guardian refusals (GUARDIAN_REFUSAL_CODES), response↔request binding
    mismatches, and invalid response signatures. §6.4's posture governs
    'no usable decision arrived' — these are different: something
    answered, and the answer is wrong in a way an attacker can induce.
    """
    _emit_deny(hook_name, f"ACS adapter: refused ({cause})")
    audit_event("guardian_refusal_fail_closed",
                cause=cause, hook=hook_name, session_id=session_id,
                **audit_extras)
    return 0


def _emit_deny(hook_name: str, msg: str) -> None:
    """Emit a deny in the hook's native response shape."""
    if hook_name == "PreToolUse":
        _emit(_pretool_response("deny", msg))
    elif hook_name in BLOCK_RESPONSE_HOOKS:
        _emit(_block_response(msg))


if __name__ == "__main__":
    sys.exit(main())
