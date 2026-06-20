"""
Integration tests for the ACS NAT middleware against the installed
nvidia-nat-core package (NAT 1.7.0+).

These tests construct a real NAT InvocationContext, run the adapter's
pre_invoke / post_invoke through the actual NAT middleware machinery,
and assert the round-trip behavior against a live example Guardian.

Requires:
  pip install nvidia-nat-core
"""
from __future__ import annotations

import asyncio
import os
import json
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

# Skip cleanly if NAT isn't installed in the environment running tests
try:
    from nat.middleware.middleware import (
        InvocationContext,
        FunctionMiddlewareContext,
    )
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

# Import adapter (it tolerates NAT missing)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from acs_adapter import ACSMiddleware, ACSGuardianDenied  # noqa: E402

if _NAT_OK:
    from acs_adapter import ACSMiddlewareConfig  # noqa: E402


HERE = Path(__file__).resolve().parent
GUARDIAN = HERE.parent.parent / "example-guardian" / "example_guardian.py"


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "_common"))
from test_harness import free_port as _find_free_port, wait_port as _wait  # noqa: E402


def _make_context(tool_name: str, args: dict) -> "InvocationContext":
    """Build a NAT InvocationContext that exercises the same path real NAT runtime would."""
    return InvocationContext(
        function_context=FunctionMiddlewareContext(
            name=tool_name,
            config=None,
            description=None,
            input_schema=None,
            single_output_schema=type(None),
            stream_output_schema=type(None),
        ),
        original_args=(),
        original_kwargs=args,
        modified_args=(),
        modified_kwargs=dict(args),
    )


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed in test environment")
class NATMiddlewareIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _find_free_port()
        env = os.environ.copy(); env["ACS_DEV_MODE"] = "1"; env.pop("ACS_HMAC_SECRET", None); env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.guardian_proc = subprocess.Popen(
            [sys.executable, str(GUARDIAN), "--port", str(cls.port)], env=env,
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
        )
        _wait("127.0.0.1", cls.port)
        cls.guardian_url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()

    def _make_middleware(self, default_deny: bool = True) -> ACSMiddleware:
        cfg = ACSMiddlewareConfig(
            guardian_url=self.guardian_url,
            default_deny=default_deny,
            session_id="nat-test",
        )
        return ACSMiddleware(cfg)

    # ----- allow path -----

    def test_safe_bash_passes_through(self) -> None:
        mw = self._make_middleware()
        ctx = _make_context("Bash", {"command": "ls -la"})
        result = asyncio.run(mw.pre_invoke(ctx))
        # allow -> return None (passthrough)
        self.assertIsNone(result)
        self.assertIsNone(ctx.action) if hasattr(ctx, "action") else None

    def test_safe_read_passes_through(self) -> None:
        mw = self._make_middleware()
        ctx = _make_context("Read", {"file_path": "/tmp/safe.txt"})
        result = asyncio.run(mw.pre_invoke(ctx))
        self.assertIsNone(result)

    # ----- deny path -----

    def test_destructive_bash_blocks(self) -> None:
        """Guardian denies destructive Bash; adapter blocks NAT invocation."""
        mw = self._make_middleware()
        ctx = _make_context("Bash", {"command": "rm -rf /home/user"})

        # On NAT 1.7.0 (no InvocationAction), block raises ACSGuardianDenied
        try:
            result = asyncio.run(mw.pre_invoke(ctx))
        except ACSGuardianDenied as e:
            self.assertIn("destructive", str(e).lower())
            return  # block via exception path (NAT 1.7.0)

        # On future NAT (has InvocationAction), block via context.action
        from nat.middleware import middleware as m
        if hasattr(m, "InvocationAction"):
            self.assertIsNotNone(ctx.action)
            self.assertEqual(ctx.action.value, "skip")
        else:
            self.fail("destructive Bash should have blocked")

    def test_write_to_protected_path_blocks(self) -> None:
        mw = self._make_middleware()
        ctx = _make_context("Write", {"file_path": "/etc/passwd", "content": "x"})
        try:
            asyncio.run(mw.pre_invoke(ctx))
            from nat.middleware import middleware as m
            self.assertTrue(hasattr(m, "InvocationAction") and ctx.action is not None)
        except ACSGuardianDenied as e:
            self.assertIn("protected", str(e).lower())

    # ----- post_invoke -----

    def test_post_invoke_allow_passes_through(self) -> None:
        mw = self._make_middleware()
        ctx = _make_context("Read", {"file_path": "/tmp/x"})
        ctx.output = "file contents"
        result = asyncio.run(mw.post_invoke(ctx))
        self.assertIsNone(result)  # allow + no modification

    # ----- fail posture -----

    def test_guardian_unreachable_default_deny_blocks(self) -> None:
        cfg = ACSMiddlewareConfig(
            guardian_url="http://127.0.0.1:1/dead",
            default_deny=True,
        )
        mw = ACSMiddleware(cfg)
        ctx = _make_context("Read", {"file_path": "/tmp/x"})
        try:
            asyncio.run(mw.pre_invoke(ctx))
            from nat.middleware import middleware as m
            self.assertTrue(hasattr(m, "InvocationAction") and ctx.action is not None)
        except ACSGuardianDenied as e:
            self.assertIn("unreachable", str(e).lower())

    def test_guardian_unreachable_fail_open(self) -> None:
        cfg = ACSMiddlewareConfig(
            guardian_url="http://127.0.0.1:1/dead",
            default_deny=False,
        )
        mw = ACSMiddleware(cfg)
        ctx = _make_context("Read", {"file_path": "/tmp/x"})
        result = asyncio.run(mw.pre_invoke(ctx))
        self.assertIsNone(result)  # fail-open: proceed


class ExtractArgumentsFromInvocationContext(unittest.TestCase):
    """Regression: NAT's middleware chain captures the function input as
    `modified_args[0]` (a Pydantic model or similar, returned by
    `Function._convert_input(value)`), NOT as `modified_kwargs`. The
    original adapter read only from `modified_kwargs` — which is empty
    on the LangChain react_agent path — so every `toolCallRequest`
    envelope carried `arguments: {}`. A real LLM-driven `rm -rf`
    against a sandbox directory ran to completion because the
    Guardian's policy had no command string to inspect.

    `_extract_arguments` MUST flatten args from EVERY shape NAT may
    use to capture the input. These tests don't need NAT installed —
    the helper is duck-typed on the context.
    """

    def _ctx(self, *, modified_args=(), modified_kwargs=None,
              input_schema=None):
        """Build a duck-typed object matching what _extract_arguments reads."""
        from types import SimpleNamespace
        return SimpleNamespace(
            modified_args=tuple(modified_args),
            modified_kwargs=dict(modified_kwargs or {}),
            function_context=SimpleNamespace(input_schema=input_schema),
        )

    def test_pydantic_v2_model_in_modified_args_extracts_fields(self) -> None:
        """The exact regression. LangChain react_agent → NAT → Pydantic
        model in modified_args[0] → adapter must surface field values."""
        try:
            from pydantic import BaseModel
        except ImportError:
            self.skipTest("pydantic not installed")
        from acs_adapter import _extract_arguments

        class ShellInput(BaseModel):
            command: str

        ctx = self._ctx(modified_args=(ShellInput(command="rm -rf /tmp/x/"),))
        args = _extract_arguments(ctx)
        self.assertEqual(args.get("command"), "rm -rf /tmp/x/",
            "REGRESSION: LLM-driven rm -rf bypassed Guardian because adapter "
            "ignored Pydantic input in modified_args[0]; field 'command' "
            "must be extracted so policy can match destructive patterns")

    def test_plain_dict_in_modified_args_extracts_keys(self) -> None:
        """NAT may also pass a raw dict if the function takes one."""
        from acs_adapter import _extract_arguments
        ctx = self._ctx(modified_args=({"command": "echo hi"},))
        self.assertEqual(_extract_arguments(ctx), {"command": "echo hi"})

    def test_modified_kwargs_still_works(self) -> None:
        """Existing path (named kwargs, e.g. from direct middleware tests)
        must still work — this is the path the integration tests above use."""
        from acs_adapter import _extract_arguments
        ctx = self._ctx(modified_kwargs={"file_path": "/tmp/x"})
        self.assertEqual(_extract_arguments(ctx), {"file_path": "/tmp/x"})

    def test_kwargs_and_args_both_present_kwargs_first(self) -> None:
        """If both shapes are populated, both should appear in the result."""
        from acs_adapter import _extract_arguments
        ctx = self._ctx(modified_args=({"command": "ls"},),
                          modified_kwargs={"timeout_s": 5})
        out = _extract_arguments(ctx)
        self.assertEqual(out.get("command"), "ls")
        self.assertEqual(out.get("timeout_s"), 5)

    def test_scalar_arg_with_schema_uses_field_name(self) -> None:
        """If the arg is a scalar (e.g. single string), name it after
        the input schema's first field — better than 'arg0' on the wire."""
        try:
            from pydantic import BaseModel
        except ImportError:
            self.skipTest("pydantic not installed")
        from acs_adapter import _extract_arguments

        class Schema(BaseModel):
            command: str

        ctx = self._ctx(modified_args=("ls -la",), input_schema=Schema)
        self.assertEqual(_extract_arguments(ctx).get("command"), "ls -la")

    def test_empty_context_returns_empty(self) -> None:
        """No args, no kwargs, no schema → empty dict, not a crash."""
        from acs_adapter import _extract_arguments
        self.assertEqual(_extract_arguments(self._ctx()), {})

    def test_dataclass_in_modified_args(self) -> None:
        from acs_adapter import _extract_arguments
        from dataclasses import dataclass

        @dataclass
        class ShellInput:
            command: str

        ctx = self._ctx(modified_args=(ShellInput(command="ls"),))
        self.assertEqual(_extract_arguments(ctx).get("command"), "ls")


if __name__ == "__main__":
    unittest.main(verbosity=2)
