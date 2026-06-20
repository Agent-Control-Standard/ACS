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


if __name__ == "__main__":
    unittest.main(verbosity=2)
