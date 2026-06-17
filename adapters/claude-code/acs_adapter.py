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
from typing import Any


# Bootstrap shared helpers from sibling adapters/_common/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
from acs_common import (  # noqa: E402
    ACS_VERSION,
    audit_event,
    coerce_uuid,
    do_handshake,
    iso8601_now,
    sign_envelope,
    validate_guardian_url,
    verify_signature,
)


GUARDIAN_URL = os.environ.get("ACS_GUARDIAN_URL", "http://127.0.0.1:8787/acs")
DEFAULT_DENY = os.environ.get("ACS_DEFAULT_DENY", "0") == "1"
HANDSHAKE_ENABLED = os.environ.get("ACS_HANDSHAKE", "1") == "1"


HOOK_MAP: dict[str, str] = {
    "SessionStart": "steps/sessionStart",
    "SessionEnd": "steps/sessionEnd",
    "UserPromptSubmit": "steps/userMessage",
    "PreToolUse": "steps/toolCallRequest",
    "PostToolUse": "steps/toolCallResult",
    "Notification": "steps/agentResponse",
    "Stop": "steps/sessionEnd",
}


SESSION_END_REASON_MAP: dict[str, str] = {
    "clear": "completed",
    "logout": "abandoned",
    "prompt_input_exit": "abandoned",
    "other": "completed",
}


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


def build_payload(event: dict[str, Any]) -> dict[str, Any]:
    name = event.get("hook_event_name", "")

    if name == "PreToolUse":
        return {
            "tool": {"name": event.get("tool_name", "")},
            "arguments": _wrap_arguments(event.get("tool_input") or {}),
        }

    if name == "PostToolUse":
        tool_response = event.get("tool_response", event.get("tool_output"))
        exit_status = "failure" if (isinstance(tool_response, dict) and tool_response.get("interrupted")) else "success"
        payload: dict[str, Any] = {
            "tool": {"name": event.get("tool_name", "")},
            "exit_status": exit_status,
            "outputs": [{"value": tool_response}] if tool_response is not None else [],
        }
        ref = _tool_use_request_id(event.get("tool_use_id"))
        if ref:
            payload["request_id_ref"] = ref
        if event.get("duration_ms") is not None:
            payload["duration_ms"] = event["duration_ms"]
        return payload

    if name == "UserPromptSubmit":
        return {"content": [{"type": "text", "value": event.get("prompt", "")}]}

    if name == "Notification":
        return {"content": [{"type": "text", "value": event.get("message", "")}]}

    if name == "SessionStart":
        out: dict[str, Any] = {}
        ctx = {k: v for k, v in (("source", event.get("source")),
                                 ("model", event.get("model")),
                                 ("transcript_path", event.get("transcript_path"))) if v}
        if ctx:
            out["platform_context"] = ctx
        return out

    if name in ("SessionEnd", "Stop"):
        raw_reason = event.get("reason") or ("completed" if name == "Stop" else "other")
        return {"reason": SESSION_END_REASON_MAP.get(raw_reason, "completed")}

    return {}


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
    if event.get("cwd"):
        metadata["cwd"] = event["cwd"]
    if event.get("transcript_path"):
        metadata["transcript_path"] = event["transcript_path"]
    if event.get("permission_mode"):
        metadata["permission_mode"] = event["permission_mode"]

    # For PreToolUse, pin request_id to a deterministic UUID derived
    # from tool_use_id so the PostToolUse can reference it.
    if method == "steps/toolCallRequest":
        ref = _tool_use_request_id(event.get("tool_use_id"))
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
            "payload": build_payload(event),
        },
    }
    sign_envelope(envelope, session_id=session_id)
    return envelope


def _maybe_handshake(event: dict[str, Any]) -> None:
    if not HANDSHAKE_ENABLED:
        return
    session_id = event.get("session_id")
    if not session_id:
        return
    do_handshake(
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


PRETOOL_PERMISSION_MAP: dict[str, str] = {
    "allow": "allow", "deny": "deny", "ask": "ask", "defer": "defer",
}

KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


def translate_response(acs_response: dict[str, Any], hook_event: str) -> dict[str, Any]:
    result = acs_response.get("result", {})
    decision = (result.get("decision") or "").lower()
    reasoning = result.get("reasoning", "")
    modifications = result.get("modifications", {})

    if decision not in KNOWN_DECISIONS and DEFAULT_DENY:
        reason = f"unknown Guardian disposition '{decision}' (default-deny)"
        if hook_event == "PreToolUse":
            return {"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }}
        if hook_event in ("PostToolUse", "UserPromptSubmit", "Stop", "SubagentStop", "PreCompact"):
            return {"decision": "block", "reason": reason}

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
            hso["permissionDecisionReason"] = f"MODIFY substituted to DENY (no parameter_overrides): {reasoning}"
            return {"hookSpecificOutput": hso}
        return {}

    if hook_event == "PostToolUse":
        if decision == "deny":
            return {"decision": "block", "reason": reasoning or "blocked by Guardian",
                    "hookSpecificOutput": {"hookEventName": "PostToolUse"}}
        if decision == "modify":
            updated = modifications.get("modified_content")
            if updated is not None:
                return {"hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": str(updated),
                    **({"additionalContext": reasoning} if reasoning else {}),
                }}
            return {"decision": "block",
                    "reason": f"MODIFY substituted to DENY (no modified_content): {reasoning}"}
        if decision in ("ask", "defer"):
            return {"decision": "block",
                    "reason": f"{decision} on post-tool not supported by Claude Code: {reasoning}"}
        return {}

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

    additional = result.get("additional_context")
    if additional:
        return {"hookSpecificOutput": {
            "hookEventName": hook_event,
            "additionalContext": str(additional),
        }}
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

    # Handshake on first call of a session (cached after). Best-effort:
    # a failed handshake follows the deployment's startup posture (§4.1).
    _maybe_handshake(event)

    request = None
    try:
        request = build_request(event)
        if not request:
            sys.stderr.write(f"acs-adapter: could not build request for {hook_name}\n")
            return _fail(hook_name, event.get("session_id"))
        response = call_guardian(request)

        # Verify response signature if signing is enabled.
        if not verify_signature(response, session_id=event.get("session_id")):
            sys.stderr.write("acs-adapter: response signature invalid\n")
            return _fail(hook_name, event.get("session_id"))

        out = translate_response(response, hook_name)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        sys.stderr.write(f"acs-adapter: Guardian unreachable: {e}\n")
        return _fail(hook_name, event.get("session_id"),
                     request_id=(request or {}).get("params", {}).get("request_id"),
                     method=(request or {}).get("method"))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"acs-adapter: adapter error: {e}\n")
        return _fail(hook_name, event.get("session_id"))

    if out:
        json.dump(out, sys.stdout)
        sys.stdout.write("\n")
    return 0


def _fail(hook_name: str = "", session_id: str | None = None, **audit_extras) -> int:
    """Apply the deployment's fail posture and record an audit event per §6.4."""
    if DEFAULT_DENY:
        # Fail-closed: emit a deny in the hook's native shape
        msg = "ACS adapter: decision-failure (default-deny)"
        if hook_name == "PreToolUse":
            json.dump({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": msg,
            }}, sys.stdout)
            sys.stdout.write("\n")
        elif hook_name in ("PostToolUse", "UserPromptSubmit", "Stop", "SubagentStop", "PreCompact"):
            json.dump({"decision": "block", "reason": msg}, sys.stdout)
            sys.stdout.write("\n")
        audit_event("decision_failure_fail_closed",
                    hook=hook_name, session_id=session_id, **audit_extras)
        return 0

    # Fail-open: proceed without a decision, but record the bypass (§6.4)
    audit_event("fail_open_bypass",
                hook=hook_name, session_id=session_id, **audit_extras)
    return 0


if __name__ == "__main__":
    sys.exit(main())
