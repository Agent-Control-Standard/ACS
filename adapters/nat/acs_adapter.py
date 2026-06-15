"""
ACS middleware for the NVIDIA Agent Toolkit (NAT / NeMo Agent Toolkit).

Wires NAT's Middleware abstraction to an ACS Guardian. Intercepts every
function (tool / sub-workflow / LLM / etc.) call configured to use this
middleware, sends an ACS JSON-RPC request to the Guardian, and applies
the verdict to NAT's invocation context.

Schema source: NAT public repo `packages/nvidia_nat_core/src/nat/middleware/`.

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

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Optional

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
    from pydantic import BaseModel, Field
except ImportError:
    BaseModel = object  # type: ignore[assignment, misc]
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

        Registered with NAT under `_type: acs_guardian` (the `name=` class kwarg
        is NAT's TypedBaseModel registration mechanism — see
        `nat/data_models/common.py`).
        """
        guardian_url: str = Field(
            default="http://127.0.0.1:8787/acs",
            description="ACS Guardian endpoint to POST requests to.",
        )
        default_deny: bool = Field(
            default=True,
            description="Block the call when the Guardian is unreachable or returns malformed responses.",
        )
        session_id: Optional[str] = Field(
            default=None,
            description="Session id sent on every request. Auto-generated per-process if absent.",
        )
        timeout_s: float = Field(
            default=5.0,
            description="Per-request timeout for the Guardian round-trip.",
        )
        target_function_or_group: Optional[str] = None
        target_location: str = "input"


# ----- Middleware class -----

class ACSMiddleware(FunctionMiddleware):  # type: ignore[misc, valid-type]
    """NAT middleware that defers each call's allow/deny/modify decision to an ACS Guardian."""

    def __init__(self, config):
        if _NAT_AVAILABLE:
            super().__init__()
        self._config = config
        self._session_id = (
            getattr(config, "session_id", None)
            or os.environ.get("ACS_SESSION_ID")
            or f"nat-{uuid.uuid4().hex[:16]}"
        )

    @property
    def enabled(self) -> bool:
        return True

    async def pre_invoke(self, context):
        """Gate the function call. Block via raising or InvocationAction.SKIP; modify args in place."""
        request = self._build_request(
            method="steps/toolCallRequest",
            tool_name=context.function_context.name,
            tool_arguments=dict(context.modified_kwargs or {}),
        )

        try:
            response = self._call_guardian(request)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            if self._config.default_deny:
                return self._block(context, f"Guardian unreachable: {e}")
            return None  # fail-open: proceed

        result = (response or {}).get("result", {})
        decision = (result.get("decision") or "").lower()
        reasoning = result.get("reasoning", "")

        if decision == "allow":
            return None  # proceed unchanged
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
            # should compose with NAT's HITL middleware
            # (nat.middleware.hitl) and have the Guardian resolve before
            # responding.
            return self._block(context, f"{decision}: {reasoning}")

        # Unknown decision: apply fail posture
        if self._config.default_deny:
            return self._block(context, f"unknown disposition: {decision}")
        return None

    async def post_invoke(self, context):
        """Record the result. Optionally modify the output."""
        request = self._build_request(
            method="steps/toolCallResult",
            tool_name=context.function_context.name,
            tool_arguments=dict(context.modified_kwargs or {}),
            result=context.output,
        )

        try:
            response = self._call_guardian(request)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            return None  # post-hoc is best-effort

        result = (response or {}).get("result", {})
        decision = (result.get("decision") or "").lower()
        if decision == "modify":
            mods = result.get("modifications", {})
            modified_content = mods.get("modified_content")
            if modified_content is not None:
                context.output = modified_content
                return context
        return None

    # ----- helpers -----

    def _block(self, context, reason: str):
        """Block the invocation. Prefer InvocationAction when available,
        fall back to raising for NAT releases that don't expose it."""
        if _HAS_INVOCATION_ACTION:
            context.action = InvocationAction.SKIP  # type: ignore[attr-defined]
            return context
        raise ACSGuardianDenied(reason)

    def _build_request(
        self,
        method: str,
        tool_name: str,
        tool_arguments: dict,
        result: Any = None,
    ) -> dict:
        params: dict[str, Any] = {
            "session_id": self._session_id,
            "step_id": str(uuid.uuid4()),
            "tool": {"name": tool_name, "arguments": tool_arguments},
        }
        if result is not None:
            params["result"] = result if isinstance(result, (str, int, float, bool, dict, list)) else str(result)
        return {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params,
            "acs_version": ACS_VERSION,
            "request_id": str(uuid.uuid4()),
            "timestamp": int(time.time() * 1000),
            "metadata": {"source": "acs-adapter-nat"},
        }

    def _call_guardian(self, request: dict) -> dict:
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
