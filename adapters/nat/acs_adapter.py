"""
ACS middleware for the NVIDIA Agent Toolkit (NAT / NeMo Agent Toolkit).

Wires NAT's Middleware abstraction to an ACS Guardian. Intercepts every
function (tool / sub-workflow / LLM / etc.) call configured to use this
middleware, sends an ACS JSON-RPC request to the Guardian, and applies
the verdict to NAT's invocation context.

Schema sources:
  - NAT public repo `packages/nvidia_nat_core/src/nat/middleware/`
  - Agent-Control-Standard/ACS `specification/v0.1.0/`

Requires:
  pip install nvidia-nat-core
  (and nvidia-nat-security if you also want to register alongside NAT's
  defense middleware suite)

Compatibility:
  - nvidia-nat-core >= 1.7 (public release). Block via raising
    ACSGuardianDenied; modify via setting context.modified_kwargs / output.
  - Future versions that expose InvocationAction.SKIP are also supported:
    if the symbol is importable, the adapter sets context.action instead
    of raising, which produces cleaner traces.

Environment variables:
  ACS_AGENT_ID    Explicit agent_id for metadata. If unset, derived from
                  config.target_function_or_group, falling back to "nat".

Usage in NAT YAML:

  middleware:
    acs_guardian:
      _type: acs_guardian
      guardian_url: http://127.0.0.1:8787/acs
      target_function_or_group: <tool-or-group-or-workflow-name>
      default_deny: true

  function_groups:
    my_tools:
      middleware: [acs_guardian]

  workflow:
    _type: react_agent
    middleware: [acs_guardian]
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Optional

# Bootstrap shared helpers from sibling adapters/_common/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_common"))
from acs_common import (  # noqa: E402
    audit_event,
    ensure_session_handshake,
    iso8601_now as _common_iso8601_now,
    sign_envelope,
    validate_guardian_url,
    verify_signature,
)

try:
    from nat.middleware.function_middleware import FunctionMiddleware
    from nat.middleware.middleware import InvocationContext
    from nat.data_models.middleware import FunctionMiddlewareBaseConfig
    _NAT_AVAILABLE = True
except ImportError:
    FunctionMiddleware = object  # type: ignore[assignment, misc]
    InvocationContext = Any  # type: ignore[assignment, misc]
    FunctionMiddlewareBaseConfig = object  # type: ignore[assignment, misc]
    _NAT_AVAILABLE = False

# Lifecycle observer support: subscribes to NAT's IntermediateStepManager
# to fire ACS sessionStart / userMessage / agentResponse / sessionEnd at
# the workflow boundary. Without this, NAT alone only fires
# toolCallRequest / toolCallResult and does not satisfy ACS-Core's
# 6-hook taxonomy minimum (conformance.md:19).
try:
    from nat.data_models.intermediate_step import IntermediateStepType  # type: ignore[import-not-found]
    from nat.builder.context import Context as _NATContext  # type: ignore[import-not-found]
    _HAS_LIFECYCLE = True
except ImportError:
    IntermediateStepType = None  # type: ignore[assignment]
    _NATContext = None  # type: ignore[assignment]
    _HAS_LIFECYCLE = False

# InvocationAction.SKIP is on the dev branch; not in NAT 1.7.0 release.
try:
    from nat.middleware.middleware import InvocationAction  # type: ignore[attr-defined]
    _HAS_INVOCATION_ACTION = True
except (ImportError, AttributeError):
    InvocationAction = None  # type: ignore[assignment]
    _HAS_INVOCATION_ACTION = False

try:
    from nat.cli.register_workflow import register_middleware
    _HAS_REGISTRATION = True
except ImportError:
    register_middleware = None  # type: ignore[assignment]
    _HAS_REGISTRATION = False

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kw: None  # type: ignore[assignment, misc]


ACS_VERSION = "0.1.0"


class ACSGuardianDenied(Exception):
    """Raised by the ACS middleware to block a function call.

    NAT's documented blocking mechanism is to raise from pre_invoke (the
    docstring: "Raises: Any exception to abort execution"). This custom
    exception type lets observers and tests distinguish a policy-driven
    block from unrelated errors.
    """


# ----- Config -----

if _NAT_AVAILABLE:

    class ACSMiddlewareConfig(FunctionMiddlewareBaseConfig, name="acs_guardian"):  # type: ignore[misc, valid-type, call-arg]
        """Config schema for the ACS NAT middleware.

        Registered with NAT under `_type: acs_guardian`.
        """
        guardian_url: str = Field(
            default="http://127.0.0.1:8787/acs",
            description="ACS Guardian endpoint to POST requests to.",
        )
        default_deny: bool = Field(
            default=False,
            description="If True, block the call when the Guardian is unreachable, returns malformed responses, or returns an unknown disposition. Default False matches the ACS spec default (§6.4 fail-open with audit event); set True for deployments that prefer fail-closed availability tradeoff.",
        )
        session_id: Optional[str] = Field(
            default=None,
            description="Session id sent on every request. Auto-generated per-process if absent. Coerced to UUID format.",
        )
        timeout_s: float = Field(
            default=5.0,
            description="Per-request timeout for the Guardian round-trip.",
        )
        target_function_or_group: Optional[str] = None
        target_location: str = "input"


# ----- Helpers (module-scope so tests can exercise them without instantiating the middleware) -----


def _iso8601_now() -> str:
    return _common_iso8601_now()


def _coerce_uuid(raw: str | None) -> str:
    """request-envelope.json:66 wants session_id as UUID. Accept a UUID
    directly; otherwise derive a stable UUID5 from whatever NAT gave us."""
    if not raw:
        return str(uuid.uuid4())
    try:
        return str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"nat:{raw}"))


def _wrap_arguments(raw: dict[str, Any]) -> dict[str, Any]:
    """tool-call-request.json:26-37 — each arg is {value, provenance?}."""
    return {k: {"value": v} for k, v in (raw or {}).items()}


def _stringify_step_data(data: Any) -> str:
    """Best-effort extraction of human-readable content from a NAT
    IntermediateStepPayload.data. The shape varies per event_type and per
    framework; we pull out a string when possible and json-dump otherwise.
    Returns empty string when there is genuinely nothing to forward."""
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    # NAT often wraps inputs/outputs in StreamEventData with .input/.output fields
    for attr in ("input", "output", "chunk", "value", "content"):
        v = getattr(data, attr, None)
        if isinstance(v, str) and v:
            return v
        if v is not None and not isinstance(v, (dict, list, type(None))):
            s = str(v)
            if s and s != "None":
                return s
    if isinstance(data, (dict, list)):
        try:
            return json.dumps(data, default=str)
        except (TypeError, ValueError):
            return str(data)
    return str(data)


KNOWN_DECISIONS = frozenset({"allow", "deny", "modify", "ask", "defer"})


# ----- Middleware class -----

class ACSMiddleware(FunctionMiddleware):  # type: ignore[misc, valid-type]
    """NAT middleware that defers each call's allow/deny/modify decision to an ACS Guardian."""

    def __init__(self, config):
        if _NAT_AVAILABLE:
            super().__init__()
        self._config = config
        self._session_id = _coerce_uuid(
            getattr(config, "session_id", None) or os.environ.get("ACS_SESSION_ID")
        )
        target = getattr(config, "target_function_or_group", None) or "nat"
        self._agent_id = os.environ.get("ACS_AGENT_ID") or f"nat:{hashlib.sha256(target.encode()).hexdigest()[:8]}"
        self._handshake_done = False
        self._lifecycle_subscribed = False
        self._lifecycle_subscription = None
        # §3 bug fix: lock around the check-then-set in
        # _ensure_lifecycle_subscribed. Without it, two parallel pre_invoke
        # calls both see _lifecycle_subscribed=False and both subscribe.
        self._lifecycle_lock = threading.Lock()
        # Edge case #6: WeakKeyDictionary fallback for frozen contexts.
        # Plain id(context) would risk collisions after Python GC
        # recycles object ids; WeakKey keys on identity not address.
        import weakref
        self._frozen_ctx_rids: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._frozen_ctx_lock = threading.Lock()

    def _ensure_handshake(self) -> None:
        if self._handshake_done or os.environ.get("ACS_HANDSHAKE", "1") != "1":
            return
        methods = ["steps/toolCallRequest", "steps/toolCallResult"]
        if _HAS_LIFECYCLE:
            methods += [
                "steps/sessionStart", "steps/userMessage",
                "steps/agentResponse", "steps/sessionEnd",
            ]
        # NAT is in-process, so we use the in-memory `_handshake_done`
        # flag as the primary guard (above). The disk cache in
        # ensure_session_handshake is the fallback that also makes
        # things idempotent across process restarts.
        ensure_session_handshake(
            guardian_url=self._config.guardian_url,
            session_id=self._session_id,
            agent_id=self._agent_id,
            platform="nat",
            methods_implemented=methods,
        )
        self._handshake_done = True

    def _ensure_lifecycle_subscribed(self) -> None:
        """Subscribe to NAT's IntermediateStepManager so workflow-boundary
        events fire ACS sessionStart / userMessage / agentResponse / sessionEnd.

        Idempotent and thread-safe: the lock around the check-then-set
        prevents two parallel pre_invoke calls from double-subscribing.
        Without the lock, every WORKFLOW event would fire its ACS hook
        multiple times.
        """
        if self._lifecycle_subscribed or not _HAS_LIFECYCLE:
            return
        with self._lifecycle_lock:
            # Re-check inside the lock — another thread may have just won
            # the race and completed the subscription.
            if self._lifecycle_subscribed:
                return
            try:
                ctx = _NATContext.get()
                mgr = ctx.intermediate_step_manager
            except Exception:  # noqa: BLE001
                # No active Context (e.g., direct middleware invocation in
                # tests without a full workflow). Silent skip — function-
                # call hooks still fire via FunctionMiddleware.
                return
            try:
                self._lifecycle_subscription = mgr.subscribe(
                    on_next=self._on_intermediate_step,
                    on_error=lambda e: audit_event(
                        "lifecycle_subscription_error",
                        session_id=self._session_id, error=str(e)),
                )
                self._lifecycle_subscribed = True
            except Exception as e:  # noqa: BLE001
                audit_event("lifecycle_subscribe_failed",
                            session_id=self._session_id, error=str(e))

    def _on_intermediate_step(self, step) -> None:
        """Subscriber callback. Translates NAT's IntermediateStepType events
        at the workflow boundary into ACS hooks. Function-level events
        (FUNCTION_START/END, TOOL_START/END, LLM_START/END) are ignored
        here because they're already covered by FunctionMiddleware's
        pre_invoke/post_invoke."""
        try:
            payload = step.payload
            event_type = payload.event_type
        except AttributeError:
            return

        if event_type == IntermediateStepType.WORKFLOW_START:
            # Workflow input becomes both sessionStart (boundary marker)
            # and userMessage (the input itself).
            self._emit_lifecycle_hook(
                "steps/sessionStart",
                payload={"platform_context": {"workflow_name": payload.name or ""}})
            input_text = _stringify_step_data(payload.data)
            if input_text:
                self._emit_lifecycle_hook(
                    "steps/userMessage",
                    payload={"content": [{"type": "text", "value": input_text}]})
        elif event_type == IntermediateStepType.WORKFLOW_END:
            # Workflow output becomes agentResponse; sessionEnd closes the boundary.
            output_text = _stringify_step_data(payload.data)
            if output_text:
                self._emit_lifecycle_hook(
                    "steps/agentResponse",
                    payload={"content": [{"type": "text", "value": output_text}]})
            self._emit_lifecycle_hook(
                "steps/sessionEnd",
                payload={"reason": "completed"})

    def _emit_lifecycle_hook(self, method: str, payload: dict) -> None:
        """Build, sign, and fire-and-forget POST a lifecycle hook.

        Errors are audited but do not interrupt the workflow — lifecycle
        emission is best-effort observability, not the enforcement path
        (that's pre_invoke / post_invoke)."""
        request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": {
                "acs_version": ACS_VERSION,
                "request_id": str(uuid.uuid4()),
                "timestamp": _iso8601_now(),
                "metadata": {
                    "agent_id": self._agent_id,
                    "session_id": self._session_id,
                    "platform": "nat",
                },
                "payload": payload,
            },
        }
        sign_envelope(request, session_id=self._session_id)
        try:
            self._call_guardian(request)
        except Exception as e:  # noqa: BLE001
            audit_event("lifecycle_hook_failed",
                        method=method, session_id=self._session_id, error=str(e))

    def _correlation_request_id(self, context) -> str:
        """Return a request_id for this invocation that is unique per call
        but stable across pre_invoke + post_invoke.

        Fast path: stash a fresh uuid4 on the context. pre_invoke and
        post_invoke share the same context object, so post_invoke reads
        back the same value to populate request_id_ref.

        Fallback for contexts that don't accept attribute assignment
        (e.g., `__slots__`-frozen): use a WeakKeyDictionary keyed by
        the context object itself. Using a WeakKey ensures the entry is
        dropped when the context is GC'd, preventing id() recycling
        from causing two distinct contexts to map to the same uuid.
        (id() collisions after GC were a real concern; WeakKey avoids
        the problem by keying on identity not address.)
        """
        existing = getattr(context, "_acs_correlation_request_id", None)
        if existing:
            return existing
        rid = str(uuid.uuid4())
        try:
            context._acs_correlation_request_id = rid
            return rid
        except (AttributeError, TypeError):
            pass
        # Frozen context — fall back to WeakKeyDictionary if the object
        # supports weak references.
        try:
            with self._frozen_ctx_lock:
                cached = self._frozen_ctx_rids.get(context)
                if cached is not None:
                    return cached
                self._frozen_ctx_rids[context] = rid
                return rid
        except TypeError:
            # Not weak-referenceable either (e.g., __slots__ without
            # __weakref__). Last resort: return the fresh uuid4 each
            # call. pre→post correlation (request_id_ref) is lost in
            # this path, but the safer alternative — keying on
            # id(context) — risks collisions after GC. Audit the
            # degradation rather than introduce a silent bug.
            audit_event("frozen_unweakrefable_context",
                        session_id=self._session_id)
            return rid

    @property
    def enabled(self) -> bool:
        return True

    async def pre_invoke(self, context):
        """Gate the function call. Block via raising or InvocationAction.SKIP; modify args in place."""
        self._ensure_handshake()
        self._ensure_lifecycle_subscribed()
        correlation_id = self._correlation_request_id(context)
        try:
            request = self._build_request(
                method="steps/toolCallRequest",
                tool_name=context.function_context.name,
                tool_arguments=dict(context.modified_kwargs or {}),
                request_id=correlation_id,
            )
            response = self._call_guardian(request)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            if self._config.default_deny:
                audit_event("decision_failure_fail_closed",
                            session_id=self._session_id,
                            method="steps/toolCallRequest",
                            error=str(e))
                return self._block(context, f"Guardian unreachable: {e}")
            audit_event("fail_open_bypass",
                        session_id=self._session_id,
                        method="steps/toolCallRequest",
                        error=str(e))
            return None
        except Exception as e:  # noqa: BLE001
            if self._config.default_deny:
                audit_event("decision_failure_fail_closed",
                            session_id=self._session_id,
                            method="steps/toolCallRequest",
                            error=str(e))
                return self._block(context, f"adapter error: {e}")
            audit_event("fail_open_bypass",
                        session_id=self._session_id,
                        method="steps/toolCallRequest",
                        error=str(e))
            return None

        if not verify_signature(response, session_id=self._session_id):
            if self._config.default_deny:
                audit_event("response_signature_invalid",
                            session_id=self._session_id,
                            method="steps/toolCallRequest")
                return self._block(context, "response signature invalid")
            audit_event("fail_open_unverified_response",
                        session_id=self._session_id,
                        method="steps/toolCallRequest")
            return None

        result = (response or {}).get("result", {})
        decision = (result.get("decision") or "").lower()
        reasoning = result.get("reasoning", "")

        if decision == "allow":
            return None
        if decision == "deny":
            return self._block(context, reasoning or "denied by Guardian")
        if decision == "modify":
            mods = result.get("modifications", {})
            overrides = mods.get("parameter_overrides")
            if isinstance(overrides, dict):
                context.modified_kwargs.update(overrides)
                return context
            return self._block(context, f"MODIFY substituted to DENY: {reasoning}")
        if decision in ("ask", "defer"):
            # NAT has no native pause-and-resume primitive on the middleware
            # boundary. Substitute block; deployments wanting ASK/DEFER
            # should compose with NAT's HITL middleware.
            return self._block(context, f"{decision}: {reasoning}")

        # Unknown disposition: fail posture
        if self._config.default_deny:
            return self._block(context, f"unknown disposition: {decision}")
        return None

    async def post_invoke(self, context):
        """Record the result. Apply Guardian's verdict to the output.

        - allow: pass through.
        - modify (with modified_content): replace context.output.
        - deny: clear context.output to None and tag with reasoning. The
          tool already ran (post_invoke fires after execution), so the
          side effect cannot be undone — but downstream consumers see no
          output. This matches Specification §6.4's output-redaction gate.
        - unknown: respect default_deny — drop output if true.
        """
        # request_id_ref points at the originating toolCallRequest so the
        # Guardian can correlate result with request (tool-call-result.json:19-23).
        correlation_id = self._correlation_request_id(context)
        try:
            request = self._build_request(
                method="steps/toolCallResult",
                tool_name=context.function_context.name,
                tool_arguments=dict(context.modified_kwargs or {}),
                result=context.output,
                request_id_ref=correlation_id,
            )
            response = self._call_guardian(request)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            audit_event("post_invoke_unreachable",
                        session_id=self._session_id,
                        method="steps/toolCallResult")
            return None
        except Exception:  # noqa: BLE001
            return None

        if not verify_signature(response, session_id=self._session_id):
            audit_event("post_invoke_signature_invalid",
                        session_id=self._session_id,
                        method="steps/toolCallResult")
            return None

        result = (response or {}).get("result", {})
        decision = (result.get("decision") or "").lower()
        reasoning = result.get("reasoning", "")

        if decision == "deny":
            # Post-hoc redaction: the tool already executed, but we
            # prevent the (potentially sensitive) output from flowing.
            context.output = None
            context.acs_post_invoke_redacted = True
            context.acs_post_invoke_reason = reasoning or "output redacted by Guardian"
            return context
        if decision == "modify":
            mods = result.get("modifications", {})
            modified_content = mods.get("modified_content")
            if modified_content is not None:
                context.output = modified_content
                return context
        if decision not in KNOWN_DECISIONS and self._config.default_deny:
            context.output = None
            context.acs_post_invoke_redacted = True
            context.acs_post_invoke_reason = f"unknown disposition '{decision}' (default-deny)"
            return context
        return None

    # ----- helpers -----

    def _block(self, context, reason: str):
        """Block the invocation. Prefer InvocationAction when available,
        fall back to raising for NAT releases that don't expose it."""
        if _HAS_INVOCATION_ACTION:
            context.action = InvocationAction.SKIP  # type: ignore[attr-defined]
            context.acs_block_reason = reason
            return context
        raise ACSGuardianDenied(reason)

    def _build_request(
        self,
        method: str,
        tool_name: str,
        tool_arguments: dict,
        result: Any = None,
        request_id: str | None = None,
        request_id_ref: str | None = None,
    ) -> dict:
        """Build a signed ACS request envelope matching request-envelope.json."""
        metadata = {
            "agent_id": self._agent_id,
            "session_id": self._session_id,
            "platform": "nat",
        }
        if method == "steps/toolCallRequest":
            payload: dict[str, Any] = {
                "tool": {"name": tool_name},
                "arguments": _wrap_arguments(tool_arguments),
            }
        else:
            if result is None:
                outputs: list[dict[str, Any]] = []
            elif isinstance(result, (str, int, float, bool, dict, list)):
                outputs = [{"value": result}]
            else:
                outputs = [{"value": str(result)}]
            payload = {
                "tool": {"name": tool_name},
                "exit_status": "success",
                "outputs": outputs,
            }
            if request_id_ref:
                payload["request_id_ref"] = request_id_ref

        envelope = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": {
                "acs_version": ACS_VERSION,
                "request_id": request_id or str(uuid.uuid4()),
                "timestamp": _iso8601_now(),
                "metadata": metadata,
                "payload": payload,
            },
        }
        sign_envelope(envelope, session_id=self._session_id)
        return envelope

    def _call_guardian(self, request: dict) -> dict:
        validate_guardian_url(self._config.guardian_url)  # SSRF: refuse file://, ftp://, etc.
        body = json.dumps(request).encode("utf-8")
        req = urllib.request.Request(
            self._config.guardian_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._config.timeout_s) as resp:
            return json.loads(resp.read().decode("utf-8"))


# ----- NAT registration -----

if _NAT_AVAILABLE and _HAS_REGISTRATION:
    @register_middleware(config_type=ACSMiddlewareConfig)  # type: ignore[misc]
    async def build_acs_middleware(config: "ACSMiddlewareConfig", builder):  # type: ignore[name-defined]
        """NAT factory entry point. Yields the middleware instance for NAT to wire up."""
        yield ACSMiddleware(config)
