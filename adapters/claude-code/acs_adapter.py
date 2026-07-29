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
                      fail-closed availability tradeoff.
  ACS_HMAC_SECRET     Shared secret for baseline HMAC-SHA256 envelope
                      signing per §10. If unset, requests are unsigned
                      (local-dev mode). ACS-Core conformance requires
                      this to be set.
  ACS_AGENT_ID        Explicit agent_id for metadata. If unset, derived
                      from cwd as `claude-code:<sha8(cwd)>`.
  ACS_HANDSHAKE       "0" disables the handshake/hello call on first
                      use. Default "1". Handshake result is cached
                      per-session in ~/.cache/acs-adapter-handshake/.
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
    audit_event,
    coerce_uuid,
    ensure_session_handshake,
    guardian_error_cause,
    iso8601_now,
    sign_envelope,
    validate_guardian_url,
    verify_signature,
)


GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
HANDSHAKE_ENABLED = os.environ.get("ACS_HANDSHAKE", "1") == "1"


# ─── Hook taxonomy ──────────────────────────────────────────────────────────

HOOK_MAP: dict[str, str] = {
    "SessionStart":     "steps/sessionStart",
    "SessionEnd":       "steps/sessionEnd",
    "UserPromptSubmit": "steps/userMessage",
    "PreToolUse":       "steps/toolCallRequest",
    "PostToolUse":      "steps/toolCallResult",
    "Notification":     "steps/agentResponse",
    "Stop":             "steps/sessionEnd",
}

# Hooks whose deny shape is {"decision": "block", "reason": "..."}
# (i.e., everything except PreToolUse, which uses hookSpecificOutput.permissionDecision).
BLOCK_RESPONSE_HOOKS = frozenset({
    "PostToolUse", "UserPromptSubmit", "Stop", "SubagentStop", "PreCompact",
})

SESSION_END_REASON_MAP: dict[str, str] = {
    "clear":             "completed",
    "logout":            "abandoned",
    "prompt_input_exit": "abandoned",
    "other":             "completed",
}

PRETOOL_PERMISSION_MAP: dict[str, str] = {
    "allow": "allow", "deny": "deny", "ask": "ask", "defer": "defer",
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


_PAYLOAD_BUILDERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "PreToolUse":       _payload_pretool_use,
    "PostToolUse":      _payload_post_tool_use,
    "UserPromptSubmit": _payload_user_prompt,
    "Notification":     _payload_notification,
    "SessionStart":     _payload_session_start,
    "SessionEnd":       _payload_session_end,
    "Stop":             _payload_session_end,
}


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    builder = _PAYLOAD_BUILDERS.get(event.get("hook_event_name", ""))
    return builder(event) if builder else {}


# ─── Envelope construction ──────────────────────────────────────────────────

def build_request(event: dict[str, Any]) -> dict[str, Any]:
    method = HOOK_MAP.get(event.get("hook_event_name", ""))
    if method is None:
        return {}

    session_id = event.get("session_id")
    if not session_id:
        return {}

    metadata: dict[str, Any] = {
        "agent_id": _agent_id(event),
        "session_id": session_id,
        "platform": "claude-code",
    }
    for k in ("cwd", "transcript_path", "permission_mode"):
        if event.get(k):
            metadata[k] = event[k]

    # For PreToolUse, pin request_id to a deterministic UUID derived
    # from tool_use_id so the matching PostToolUse can reference it.
    request_id = (_tool_use_request_id(event.get("tool_use_id"))
                  if method == "steps/toolCallRequest" else None) or str(uuid.uuid4())

    envelope = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": {
            "acs_version": ACS_VERSION,
            "request_id": request_id,
            "timestamp": iso8601_now(),
            "metadata": metadata,
            "payload": build_payload(event),
        },
    }
    sign_envelope(envelope, session_id=session_id)
    return envelope


def _maybe_handshake(event: dict[str, Any]) -> None:
    """Called on every hook event.

    Looks like 'handshake every event', but `ensure_session_handshake`
    is idempotent: the FIRST event of a session_id triggers a real
    handshake/hello POST and writes the negotiated ServerHello to
    ~/.cache/acs-adapter-handshake/. Every subsequent event for the
    same session_id reads that file and returns without a network call.
    """
    if not HANDSHAKE_ENABLED:
        return
    session_id = event.get("session_id")
    if not session_id:
        return
    ensure_session_handshake(
        guardian_url=GUARDIAN_URL,
        session_id=session_id,
        agent_id=_agent_id(event),
        platform="claude-code",
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


# ─── Response translation — dispatch table, one function per hook ─────────

def _translate_pretool(decision: str, reasoning: str,
                        modifications: dict) -> dict[str, Any]:
    if decision in PRETOOL_PERMISSION_MAP:
        return _pretool_response(PRETOOL_PERMISSION_MAP[decision], reasoning)
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

    # Unknown disposition under fail-closed → emit a deny in the hook's shape.
    if decision not in KNOWN_DECISIONS and DEFAULT_DENY:
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
        return 0

    # Handshake on first call of a session (cached after). Best-effort:
    # a failed handshake follows the deployment's startup posture (§4.1).
    _maybe_handshake(event)

    request = None
    try:
        request = build_request(event)
        if not request:
            sys.stderr.write(f"acs-adapter: could not build request for {hook_name}\n")
            return _fail(hook_name, event.get("session_id"),
                         cause="adapter_build_failed")
        response = call_guardian(request)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
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

    # Guardian responded — was it a result or a JSON-RPC error?
    # An `error` means the Guardian explicitly rejected this envelope,
    # which is NOT a transport failure. §6.4 collapses them but the
    # cause field tells operators which case fired so they can act.
    if "error" in response:
        err = response.get("error") or {}
        code = err.get("code")
        cause = guardian_error_cause(code)
        sys.stderr.write(
            f"acs-adapter: Guardian returned JSON-RPC error "
            f"{code} ({cause}): {err.get('message','')}\n")
        return _fail(hook_name, event.get("session_id"),
                     cause=cause,
                     error_code=code,
                     error_message=err.get("message"),
                     request_id=(request or {}).get("params", {}).get("request_id"),
                     method=(request or {}).get("method"))

    # Response signature check (only relevant when signing is enabled).
    if not verify_signature(response, session_id=event.get("session_id")):
        sys.stderr.write("acs-adapter: response signature invalid\n")
        return _fail(hook_name, event.get("session_id"),
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
    ACS_DEFAULT_DENY; the `cause` field tells operators what actually
    went wrong so a malformed envelope (client bug) doesn't get
    confused with an unreachable Guardian (ops issue).
    """
    if DEFAULT_DENY:
        msg = f"ACS adapter: decision-failure ({cause})"
        if hook_name == "PreToolUse":
            _emit(_pretool_response("deny", msg))
        elif hook_name in BLOCK_RESPONSE_HOOKS:
            _emit(_block_response(msg))
        audit_event("decision_failure_fail_closed",
                    cause=cause, hook=hook_name, session_id=session_id,
                    **audit_extras)
        return 0

    audit_event("fail_open_bypass",
                cause=cause, hook=hook_name, session_id=session_id,
                **audit_extras)
    return 0


if __name__ == "__main__":
    sys.exit(main())
