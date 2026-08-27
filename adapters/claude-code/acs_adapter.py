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
try:
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
        modify_composition_violation,
        normalize_decision,
        response_matches_request,
        save_session_state,
        sign_envelope,
        validate_guardian_url,
        verify_signature,
    )
except ImportError as _bootstrap_error:
    # acs_common hard-requires rfc8785 (§10 permits no alternative
    # canonicalization), so a missing dependency kills this module before
    # main() runs. Claude Code proceeds on any nonzero exit except 2, so
    # dying here is an ungoverned step with no audit event (against
    # §6.4:158) that also ignores ACS_DEFAULT_DENY (against §6.4:156).
    # Handled with the standard library only: audit_event and the response
    # builders live in the module that failed to load.
    def _degraded_exit() -> int:
        if os.environ.get("ACS_DISABLED") == "1":
            # The documented kill switch is read in main(), which never runs
            # on this path. An operator who set it must still get a bypass.
            sys.stderr.write("acs-adapter: ACS_DISABLED=1, hook bypassed\n")
            return 0
        try:
            _event = json.loads(sys.stdin.read() or "{}")
        except ValueError:
            _event = {}
        _hook = _event.get("hook_event_name", "")
        _deny = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
        _line = "ACS_AUDIT " + json.dumps({
            "acs_audit_event": "adapter_unavailable",
            "hook": _hook,
            "posture": "deny" if _deny else "proceed",
            "error": str(_bootstrap_error).split("\n")[0],
            "detail": "adapter could not load; no envelope was sent",
        })
        sys.stderr.write(_line + "\n")
        _sink = os.environ.get("ACS_AUDIT_FILE", "").strip()
        if _sink:
            try:
                _fd = os.open(_sink, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(_fd, "a") as _f:
                    _f.write(_line + "\n")
            except OSError:
                pass
        if not _deny:
            return 0
        if _hook == "PreToolUse":
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason":
                    "ACS adapter unavailable (dependency missing); "
                    "failing closed per the deployment posture",
            }}))
            return 0
        if _hook == "UserPromptSubmit":
            print(json.dumps({
                "decision": "block",
                "reason": "ACS adapter unavailable (dependency missing); "
                          "failing closed per the deployment posture",
            }))
            return 0
        return 0

    if __name__ == "__main__":
        raise SystemExit(_degraded_exit())
    raise


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
ADAPTER_VERSION = "0.1.2"

GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
HANDSHAKE_ENABLED = os.environ.get("ACS_HANDSHAKE", "1") == "1"

# Effective fail posture = most-restrictive of the local env var and the
# Guardian's negotiated ServerHello `on_decision_failure` (§6.4 says the
# posture is declared in the handshake — previously the ServerHello was
# fetched, cached, and never read, so the Guardian's declared posture had
# no effect; PR #22 review). Updated once per invocation in main().
_SERVER_DENY = False

# Round-trip decision timeout. §6.4:154 says the Observed Agent MUST wait
# up to the NEGOTIATED timeout (timeout_config, §4), not a hardcoded one:
# against a Guardian negotiating e.g. 30s, a decision arriving at 6s under
# a hardcoded 5s became a bogus decision-failure/fail-open (PR #22 spec
# audit). Seeded from the ServerHello's timeout_config.default_ms in
# main(); the 5s default is the local floor when no handshake happened.
_DECISION_TIMEOUT_S = 5.0


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
    # Stop fires at the END OF A TURN (every reply), not session end.
    # steps/sessionEnd "seals the chain" once per session (hooks.md:296),
    # so mapping Stop there sealed it after every reply; steps/turnEnd is
    # the correct per-turn boundary (PR #22 spec audit A10/#11). The turn
    # is opened by an explicit steps/turnStart on UserPromptSubmit.
    "Stop":             "steps/turnEnd",
    "SubagentStop":     "steps/subagentStop",
}

# In-turn steps carry metadata.turn_id (request-envelope.json:69); session-
# level steps (sessionStart/sessionEnd) and the spawn gate do not open under
# the parent's turn. turnStart sets it; turnEnd echoes it.
_IN_TURN_METHODS = frozenset({
    "steps/userMessage", "steps/toolCallRequest", "steps/toolCallResult",
    "steps/agentResponse", "steps/turnEnd",
})

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

# Hooks whose deny shape is {"decision": "block", "reason": "..."} AND whose
# block actually prevents the action.
ENFORCEABLE_BLOCK_HOOKS = frozenset({
    "PostToolUse", "UserPromptSubmit",
})

# Not decision-eligible per the hook schemas. subagent-stop.json:5 says
# "Not decision-eligible, the subagent has already terminated", and
# hooks.md:290 says the same for turn end. Claude Code reads
# {"decision":"block"} on these as "do not stop, continue the
# conversation", so emitting one inverts a fail-closed posture into
# unbounded activity. A DENY or a decision failure on these hooks is
# recorded and nothing else.
AUDIT_ONLY_HOOKS = frozenset({
    "Stop", "SubagentStop",
})

SESSION_END_REASON_MAP: dict[str, str] = {
    "clear":             "completed",
    # `resume` = this session ended because it was resumed into a new one
    # (Claude Code hooks reference: reason ∈ clear|resume|logout|
    # prompt_input_exit|other); previously unmapped → fell to "completed"
    # (PR #22 host audit).
    "resume":            "completed",
    "logout":            "abandoned",
    "prompt_input_exit": "abandoned",
    "other":             "completed",
}

# Claude Code's permissionDecision accepts allow | deny | ask — there is
# no native "defer". This adapter substitutes DEFER→deny so an
# unresolvable verdict on the gate hook can't pass through as a value the
# framework ignores. NOTE: this is DEPLOYMENT behavior, not spec-mandated
# — §9.2 puts disposition substitution on the GUARDIAN, and the §6
# `timeout_decision: deny` default governs an EXPIRED defer, not an
# instant client-side substitution (PR #22 spec audit B5). The
# substitution is audited so its rate is visible.
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
    """Build Claude Code's generic block shape, used only by the hooks
    where a block actually prevents the action: PostToolUse and
    UserPromptSubmit (ENFORCEABLE_BLOCK_HOOKS). Stop/SubagentStop must
    never receive one — Claude Code reads a block there as "do not
    stop"."""
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
    dur = event.get("duration_ms")
    # tool-call-result.json requires an INTEGER; Claude Code documents
    # duration_ms as a number, so coerce (a raw float was schema-invalid
    # on the wire — PR #22 spec audit fidelity note).
    if isinstance(dur, (int, float)) and not isinstance(dur, bool):
        payload["duration_ms"] = int(dur)
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
        artifact the field exists to produce. A normative schema change
        carried in this PR would make the field optional for chain-less
        frameworks; that change still needs explicit spec-owner approval.
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


# ─── Turn tracking ────────────────────────────────────────────────────────
# A turn opens on UserPromptSubmit (an explicit steps/turnStart) and closes
# on Stop (steps/turnEnd). The turn_id lives in the same disk-backed
# per-session state the Cursor adapter uses, so every in-turn step stamps
# metadata.turn_id and the turnEnd carries the matching id.

def _turn_ws(event: dict[str, Any]) -> str | None:
    return event.get("cwd") or None


def _current_turn_id(session_id: str | None, event: dict[str, Any]) -> str | None:
    if not session_id:
        return None
    return load_session_state(session_id, workspace=_turn_ws(event)).get("turn_id")


def _open_turn(session_id: str, turn_id: str, event: dict[str, Any]) -> None:
    st = load_session_state(session_id, workspace=_turn_ws(event))
    st["turn_id"] = turn_id
    save_session_state(session_id, st, workspace=_turn_ws(event))


def _close_turn(session_id: str, event: dict[str, Any]) -> None:
    st = load_session_state(session_id, workspace=_turn_ws(event))
    st.pop("turn_id", None)
    save_session_state(session_id, st, workspace=_turn_ws(event))


def _payload_turn_end(event: dict[str, Any]) -> dict[str, Any]:
    """steps/turnEnd — closes the turn opened at the last UserPromptSubmit.
    turn_id comes from session state (empty if no turn is open, in which
    case build_request skips the emission). Claude's Stop fires on normal
    turn completion and carries no error discriminator, so outcome is
    'completed'."""
    turn_id = _current_turn_id(event.get("session_id"), event)
    return {"turn_id": turn_id or "", "outcome": "completed"}


_PAYLOAD_BUILDERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "PreToolUse":       _payload_pretool_use,
    "PostToolUse":      _payload_post_tool_use,
    "UserPromptSubmit": _payload_user_prompt,
    "Notification":     _payload_notification,
    "SessionStart":     _payload_session_start,
    "SessionEnd":       _payload_session_end,
    "Stop":             _payload_turn_end,
    "SubagentStop":     _payload_subagent_stop,
}


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    builder = _PAYLOAD_BUILDERS.get(event.get("hook_event_name", ""))
    return builder(event) if builder else {}


# ─── Envelope construction ──────────────────────────────────────────────────

def _is_subagent_spawn(event: dict[str, Any]) -> bool:
    """True when this PreToolUse IS a subagent spawn.

    Current Claude Code spawns subagents via the `Agent` tool — the
    official hooks reference (fetched 2026-08-22) documents "##### Agent
    — Spawns a subagent" with tool_input {prompt, description,
    subagent_type, model}, and "use a PostToolUse hook on the `Agent`
    tool" for subagent post-processing. Older builds used the name
    `Task`, so match BOTH for forward/backward compatibility. The
    separate `TaskCreate` / task-list feature is NOT a subagent spawn and
    is deliberately not matched here (previously this matched only
    "task", so the gate was dead code on current Claude Code — PR #22
    spec/host audit)."""
    return (event.get("hook_event_name") == "PreToolUse"
            and (event.get("tool_name") or "").lower() in ("agent", "task"))


def _payload_subagent_start(event: dict[str, Any]) -> dict[str, Any]:
    """steps/subagentStart from PreToolUse on the Agent tool (or legacy Task).

    For subagent-capable clients, subagentStart is the confused-deputy
    spawn gate. PR #21 (open; not in this branch) proposes promoting it
    to the Core floor; the gate wiring stands on its own. Claude Code is
    subagent-capable: the Agent tool call (legacy: Task) is the observable
    spawn boundary. Mapping it to a
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
                    detail="PreToolUse(Agent/Task) carried no tool_use_id; "
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

    # The Agent tool (legacy: Task) is Claude Code's subagent spawn — route it to the
    # dedicated confused-deputy gate instead of the generic tool hook.
    subagent_spawn = _is_subagent_spawn(event)
    if subagent_spawn:
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

    # Stamp the open turn's id on in-turn steps (request-envelope.json:69).
    if method in _IN_TURN_METHODS:
        tid = _current_turn_id(session_id, event)
        if tid:
            metadata["turn_id"] = tid

    # steps/turnEnd needs a turn_id (>=1); if no turn is open there is
    # nothing to close honestly, so skip the emission (main audits it).
    if method == "steps/turnEnd" and not _current_turn_id(session_id, event):
        return {}

    # For PreToolUse (including the Task→subagentStart remap), pin
    # request_id to a deterministic UUID derived from tool_use_id so the
    # matching PostToolUse can reference it.
    request_id = (_tool_use_request_id(event.get("tool_use_id"))
                  if event.get("hook_event_name") == "PreToolUse"
                  else None) or str(uuid.uuid4())

    payload = (_payload_subagent_start(event) if subagent_spawn
               else build_payload(event))
    if subagent_spawn:
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


def build_turn_start_request(event: dict[str, Any], turn_id: str) -> dict[str, Any]:
    """steps/turnStart opening the turn for a UserPromptSubmit. turn_id
    SHOULD equal the envelope's request_id (turn-start.json), so we use it
    for both. triggered_by is user_message — a user prompt opened this
    turn. Decision-eligible: a Guardian MAY deny to block the whole turn."""
    session_id = event.get("session_id") or ""
    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": session_id,
        "platform": "claude-code",
        "adapter_version": ADAPTER_VERSION,
        "turn_id": turn_id,
    }
    for k in ("cwd", "transcript_path", "permission_mode"):
        if event.get(k):
            metadata[k] = event[k]
    envelope = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "steps/turnStart",
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": turn_id,
            "timestamp": iso8601_now(),
            "metadata": metadata,
            "payload": {"turn_id": turn_id, "triggered_by": "user_message"},
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
        # ACS_HANDSHAKE=0 skips the §4-REQUIRED handshake. This is a
        # dev/test switch and a session run this way is NON-CONFORMANT —
        # record it so the bypass is visible rather than silent (§4.1:77;
        # PR #22 spec audit B3). Mirrors the Guardian's ACS_DEV_MODE,
        # which prints "NOT satisfied".
        audit_event("handshake_disabled_nonconformant",
                    session_id=event.get("session_id"),
                    detail="ACS_HANDSHAKE=0 — §4 handshake skipped; "
                           "session is NON-CONFORMANT")
        return None
    session_id = event.get("session_id")
    if not session_id:
        return None
    return ensure_session_handshake(
        guardian_url=GUARDIAN_URL,
        session_id=session_id,
        agent_id=_agent_id(event),
        platform="claude-code",
        # steps/subagentStart (PreToolUse→Agent remap) and steps/turnStart
        # (emitted on UserPromptSubmit alongside userMessage) are not
        # HOOK_MAP values — advertise them explicitly so advertised ==
        # emitted (PR #22 review). steps/turnEnd already comes from
        # HOOK_MAP.values() via Stop.
        methods_implemented=(list(HOOK_MAP.values())
                             + ["steps/subagentStart", "steps/turnStart"]),
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
        with urllib.request.urlopen(req, timeout=_DECISION_TIMEOUT_S) as resp:
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
                        modifications: dict,
                        original_input: dict) -> dict[str, Any]:
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
        # §6.3:146 — a modifications object that breaks the composition
        # rules (both shapes, or overlapping structured targets) is
        # un-interpretable; fail closed to DENY rather than half-apply it.
        violation = modify_composition_violation(modifications)
        if violation:
            audit_event("modify_composition_invalid", hook="PreToolUse",
                        detail=violation)
            return _pretool_response(
                "deny", f"MODIFY refused ({violation}); failing closed per §6.3:146")
        if modifications.get("redactions"):
            # Claude's updatedInput can replace arguments, but it exposes no
            # native JSON-Pointer redaction operation.  Applying sibling
            # parameter_overrides while dropping redactions would change the
            # Guardian's decision. Treat the valid-but-unrealizable compound
            # edit as DENY until the whole modification can be applied.
            audit_event("modify_unapplied_redactions", hook="PreToolUse")
            return _pretool_response(
                "deny", "MODIFY refused: Claude Code cannot apply the "
                "requested redactions without dropping part of the decision")
        overrides = modifications.get("parameter_overrides")
        # Must be an OBJECT — a string/list override cannot be applied as
        # updatedInput and §6.3:146 says a modification whose intent can't
        # be realized fails closed to DENY (previously a non-dict override
        # sailed through as allow — PR #22 adversarial probing).
        if isinstance(overrides, dict):
            # parameter_overrides are per-argument EDITS onto the existing
            # input (modifications.json). But Claude Code's updatedInput
            # REPLACES the whole input, so send original + overrides
            # merged — sending overrides alone silently drops every
            # non-overridden argument, e.g. a timeout (PR #22 spec audit).
            merged = {**original_input, **overrides}
            return _pretool_response("allow", reasoning, updated_input=merged)
        return _pretool_response(
            "deny",
            f"MODIFY substituted to DENY (no usable parameter_overrides): {reasoning}",
        )
    return {}


def _translate_posttool(decision: str, reasoning: str,
                         modifications: dict,
                         original_input: dict) -> dict[str, Any]:
    if decision == "deny":
        return _block_response(reasoning or "blocked by Guardian", "PostToolUse")
    if decision == "modify":
        violation = modify_composition_violation(modifications)
        if violation:
            audit_event("modify_composition_invalid", hook="PostToolUse",
                        detail=violation)
            return _block_response(
                f"MODIFY refused ({violation}); failing closed per §6.3:146")
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
                            modifications: dict,
                            original_input: dict) -> dict[str, Any]:
    if decision == "allow":
        return {}
    if decision == "deny":
        return _block_response(reasoning or "blocked by Guardian")
    # Claude Code's prompt hook can only allow or block — it has no native
    # way to edit the prompt or pause for approval. So ask/defer/modify all
    # fail closed to a block rather than silently proceeding: an arrived
    # restrictive decision the host can't apply MUST NOT execute as allow
    # (§6.4; PR #22 spec audit — modify previously fell through to a silent
    # allow here). Audited so the substitution is visible.
    audit_event("prompt_decision_substituted_block",
                disposition=decision, hook="UserPromptSubmit")
    return _block_response(
        f"{decision} on user prompt not applicable at this hook — blocking: {reasoning}")


def _translate_session_stop(decision: str, reasoning: str,
                             modifications: dict,
                             original_input: dict) -> dict[str, Any]:
    """Stop / SubagentStop are not decision-eligible (subagent-stop.json:5:
    "the subagent has already terminated"). A DENY cannot be enforced here,
    and Claude Code reads {"decision":"block"} on these events as "do not
    stop, continue the conversation", so emitting one would turn a denial
    into an instruction to keep working. Record it and emit nothing."""
    if decision in ("deny", "ask", "defer"):
        audit_event("unenforceable_decision", decision=decision,
                    reason=reasoning or "(none)")
    return {}


_TRANSLATORS: dict[str, Callable[[str, str, dict, dict], dict[str, Any]]] = {
    "PreToolUse":       _translate_pretool,
    "PostToolUse":      _translate_posttool,
    "UserPromptSubmit": _translate_user_prompt,
    "Stop":             _translate_session_stop,
    "SubagentStop":     _translate_session_stop,
}


def translate_response(acs_response: dict[str, Any], hook_event: str,
                       original_input: dict | None = None) -> dict[str, Any]:
    # normalize_decision coerces every field to a safe type and never
    # raises — a non-string `decision` / non-dict `modifications` from a
    # buggy or hostile Guardian must not throw here, because this runs
    # OUTSIDE main()'s try/except and an uncaught error is exit 1, which
    # Claude Code proceeds on (PR #22 review, found by adversarial probing).
    decision, reasoning, modifications = normalize_decision(
        acs_response.get("result"))

    # The decision ARRIVED but its `decision` field cannot be interpreted
    # (not one of the five dispositions). We fail closed rather than let it
    # proceed. NOTE: the exact spec basis is unsettled — §6.4:156 lists a
    # "malformed response" among decision failures (→ posture), while an
    # arrived-and-unusable verdict reads like the §6.3:146 fail-closed
    # rule; the two rub together for this case and a §6.4 clarifying
    # sentence is tracked in issue #32. We choose the safe reading (deny),
    # labeled as deliberate hardening rather than citing a section that
    # doesn't squarely cover it (PR #22 spec audit B4).
    if decision not in KNOWN_DECISIONS:
        audit_event("unusable_disposition",
                    disposition=decision or "(missing)", hook=hook_event)
        reason = (f"unusable Guardian disposition '{decision}' — cannot be "
                  f"interpreted; failing closed (see issue #32)")
        if hook_event == "PreToolUse":
            return _pretool_response("deny", reason)
        # Stop and SubagentStop are deliberately absent. Claude Code reads
        # {"decision":"block"} on those as "do not stop", so a block there
        # increases activity instead of preventing it.
        if hook_event in ENFORCEABLE_BLOCK_HOOKS:
            return _block_response(reason)
        return {}

    translator = _TRANSLATORS.get(hook_event)
    if translator:
        return translator(decision, reasoning, modifications, original_input or {})

    # Informational hooks (SessionStart, SessionEnd, Notification) —
    # surface the Guardian's `reasoning` as Claude Code's additionalContext
    # if there is any, else empty. (Reads `reasoning`, a real AcsResult
    # field — the previous `result.additional_context` was an invented
    # response field not in response-envelope.json; PR #22 spec audit.)
    if reasoning:
        return {"hookSpecificOutput": {
            "hookEventName": hook_event,
            "additionalContext": reasoning,
        }}
    return {}


# ─── Main flow ──────────────────────────────────────────────────────────────

def _guardian_roundtrip(request: dict[str, Any], hook_name: str,
                        session_id: str | None) -> tuple[dict | None, int | None]:
    """POST one request and validate the response. Returns
    (response, terminal):
      - (result_dict, None): a good, bound, signed result the caller
        should translate.
      - (None, exit_code): a terminal fail/force_deny was ALREADY emitted
        in the hook's shape; the caller returns exit_code.
    Encapsulates transport / refusal / binding / signature handling so the
    turnStart pre-step and the main step share one implementation
    (PR #22 turn-tracking: two round-trips per prompt)."""
    try:
        response = call_guardian(request)
    except RequestTooLargeError as e:
        sys.stderr.write(f"acs-adapter: envelope exceeds body cap: {e}\n")
        return None, _force_deny(hook_name, session_id,
                                 cause="request_exceeds_max_payload",
                                 body_bytes=e.args[0],
                                 method=request.get("method"))
    except GuardianHTTPRefusalError as e:
        code = e.jsonrpc_error.get("code")
        cause = (guardian_error_cause(code) if code is not None
                 else f"http_{e.status}_refusal")
        sys.stderr.write(
            f"acs-adapter: Guardian refused at HTTP layer ({e.status}, {cause})\n")
        return None, _force_deny(hook_name, session_id, cause=cause,
                                 http_status=e.status, error_code=code,
                                 error_message=e.jsonrpc_error.get("message"),
                                 method=request.get("method"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        reason = getattr(e, "reason", None)
        is_timeout = isinstance(e, TimeoutError) or isinstance(reason, TimeoutError)
        if is_timeout:
            cause = "decision_timeout"
            sys.stderr.write(
                f"acs-adapter: decision timed out after {_DECISION_TIMEOUT_S:g}s: {e}\n")
        else:
            cause = "transport_failure"
            sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return None, _fail(hook_name, session_id, cause=cause,
                           request_id=request.get("params", {}).get("request_id"),
                           method=request.get("method"), error=str(e))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return None, _fail(hook_name, session_id,
                           cause="adapter_exception", error=str(e))

    # Bind response to THIS request — a captured signed ALLOW for a benign
    # call verifies fine when replayed against a dangerous one. Mis-bound
    # is attacker-shaped: fail closed, never posture.
    if not response_matches_request(request, response):
        sys.stderr.write("acs-adapter: response not bound to request\n")
        return None, _force_deny(hook_name, session_id,
                                 cause="response_binding_mismatch")

    if "error" in response:
        # Errors are signed too (conformance.md:23); an unverifiable error
        # under fail-open is an allow. Refusals (alive + rejected, all
        # attacker-reachable) fail closed regardless of posture.
        if not verify_signature(response, session_id=session_id):
            sys.stderr.write("acs-adapter: error response signature invalid\n")
            claimed = response.get("error") or {}
            return None, _force_deny(
                hook_name, session_id, cause="error_signature_invalid",
                claimed_error_code=claimed.get("code"),
                claimed_cause=guardian_error_cause(claimed.get("code")))
        err = response.get("error") or {}
        code = err.get("code")
        cause = guardian_error_cause(code)
        sys.stderr.write(
            f"acs-adapter: Guardian returned JSON-RPC error {code} ({cause}): "
            f"{err.get('message','')}\n")
        common = dict(cause=cause, error_code=code,
                      error_message=err.get("message"),
                      request_id=request.get("params", {}).get("request_id"),
                      method=request.get("method"))
        if is_guardian_refusal(code):
            return None, _force_deny(hook_name, session_id, **common)
        return None, _fail(hook_name, session_id, **common)

    if not verify_signature(response, session_id=session_id):
        sys.stderr.write("acs-adapter: response signature invalid\n")
        return None, _force_deny(hook_name, session_id,
                                 cause="response_signature_invalid")
    return response, None


def main() -> int:
    global _SERVER_DENY, _DECISION_TIMEOUT_S
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(f"acs-adapter (claude-code) {ADAPTER_VERSION}")
        return 0
    if os.environ.get("ACS_DISABLED") == "1":
        # Incident kill switch: no Guardian traffic, no output. Every step
        # proceeds without a decision while active, so record a STRUCTURED
        # audit event (stderr + ACS_AUDIT_FILE) rather than a bare stderr
        # line — §6.4:158 requires the bypass to be visible, and an
        # operator scanning the durable audit sink must see it (PR #22
        # spec audit B11).
        audit_event("acs_disabled_bypass",
                    detail="ACS_DISABLED=1 — hook bypassed with no Guardian "
                           "traffic; every step proceeds ungoverned")
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
    # §6.4:154 — wait up to the NEGOTIATED timeout, not a hardcoded one.
    if server_hello:
        default_ms = (server_hello.get("timeout_config") or {}).get("default_ms")
        if isinstance(default_ms, (int, float)) and default_ms > 0:
            _DECISION_TIMEOUT_S = default_ms / 1000.0

    session_id = event.get("session_id")

    # Turn tracking: a UserPromptSubmit OPENS a turn with an explicit,
    # decision-eligible steps/turnStart BEFORE the userMessage. A Guardian
    # MAY deny to block the whole turn (turn-start.json); the deny lands in
    # the prompt's own block shape so the prompt is blocked.
    if hook_name == "UserPromptSubmit":
        turn_id = str(uuid.uuid4())
        ts_response, terminal = _guardian_roundtrip(
            build_turn_start_request(event, turn_id), "UserPromptSubmit", session_id)
        if terminal is not None:
            return terminal
        ts_decision, ts_reason, _ = normalize_decision(ts_response.get("result"))
        if ts_decision != "allow":
            # turnStart is a gate boundary — the host can't apply
            # modify/ask/defer to "a turn is starting", so any non-allow
            # blocks the prompt (fail closed). Audited.
            audit_event("turn_start_blocked", turn_id=turn_id,
                        disposition=ts_decision or "(unusable)")
            _emit(_block_response(
                f"turn blocked at start ({ts_decision or 'unusable'}): {ts_reason}"))
            return 0
        _open_turn(session_id, turn_id, event)

    try:
        request = build_request(event)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(hook_name, session_id, cause="adapter_exception", error=str(e))
    if not request:
        if hook_name == "Stop":
            # turnEnd with no open turn: nothing to close honestly. Record
            # it rather than fabricate a turn_id (PR #22 turn-tracking).
            audit_event("turn_end_no_open_turn", session_id=session_id)
            return 0
        sys.stderr.write(f"acs-adapter: could not build request for {hook_name}\n")
        return _fail(hook_name, session_id, cause="adapter_build_failed")

    response, terminal = _guardian_roundtrip(request, hook_name, session_id)
    if terminal is not None:
        return terminal

    # Defense in depth: translate_response runs OUTSIDE _guardian_roundtrip's
    # try/except, so a bug here would escape to exit 1 = host proceeds
    # (fail-open). normalize_decision makes known inputs total; this guard
    # makes any FUTURE translation bug fail CLOSED (PR #22 review).
    try:
        _emit(translate_response(response, hook_name,
                                 original_input=event.get("tool_input") or {}))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: translate error: {e}\n")
        return _force_deny(hook_name, session_id,
                           cause="adapter_translate_exception", error=str(e))

    # Close the turn after the turnEnd has been emitted/recorded.
    if hook_name == "Stop":
        _close_turn(session_id, event)
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
    """Emit a deny in the hook's native response shape — except on the
    audit-only hooks, where no enforceable shape exists and a block
    would instruct Claude Code to keep going."""
    if hook_name in AUDIT_ONLY_HOOKS:
        audit_event("unenforceable_decision", hook=hook_name, reason=msg)
        return
    if hook_name == "PreToolUse":
        _emit(_pretool_response("deny", msg))
    elif hook_name in ENFORCEABLE_BLOCK_HOOKS:
        _emit(_block_response(msg))


if __name__ == "__main__":
    sys.exit(main())
