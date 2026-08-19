"""
Tests that target the 3 most-likely production failure modes identified
in the harsh-reviewer audit.

Each test names the failure mode in plain English, exercises the exact
production scenario that would trigger it, and asserts the safe
behavior. A regression on any of these is a real outage waiting to
happen.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

try:
    from nat.builder.context import Context, ContextState
    from nat.builder.intermediate_step_manager import IntermediateStepManager
    from nat.data_models.intermediate_step import (
        IntermediateStepPayload, IntermediateStepType, StreamEventData,
    )
    _NAT_OK = True
except ImportError:
    _NAT_OK = False

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from acs_adapter import ACSMiddleware  # noqa: E402

if _NAT_OK:
    from acs_adapter import ACSMiddlewareConfig  # noqa: E402

HERE = Path(__file__).resolve().parent
GUARDIAN_SCRIPT = HERE.parent.parent / "example-guardian" / "example_guardian.py"


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "_common"))
from test_harness import free_port as _free_port, wait_port as _wait  # noqa: E402


class RecordingGuardian(BaseHTTPRequestHandler):
    """Test Guardian that records every received method + tracks
    duplicate request_ids per session (so we can assert no replay)."""
    recorded: list = []
    seen_per_session: dict = {}
    lock = threading.Lock()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        method = body.get("method", "")
        params = body.get("params") or {}
        meta = params.get("metadata") or {}
        sid = meta.get("session_id", "")
        rid = params.get("request_id", "")
        with RecordingGuardian.lock:
            RecordingGuardian.recorded.append({"method": method, "session_id": sid, "request_id": rid})
            seen = RecordingGuardian.seen_per_session.setdefault(sid, set())
            if rid in seen and rid:
                # Simulate the real Guardian's REPLAY_DETECTED behavior
                reply = json.dumps({
                    "jsonrpc": "2.0", "id": body.get("id"),
                    "error": {"code": -32005, "message": f"REPLAY_DETECTED: {rid}"},
                }).encode("utf-8")
            else:
                if rid:
                    seen.add(rid)
                reply = json.dumps({
                    "jsonrpc": "2.0", "id": body.get("id"),
                    "result": {"type": "final", "acs_version": "0.1.0",
                               "request_id": rid, "decision": "allow",
                               "chain_hash": "0" * 64},
                }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args, **kwargs):
        return


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class FailureMode1_DuplicateToolCallReplayDetected(unittest.TestCase):
    """FAILURE MODE #1: NAT _correlation_request_id is uuid5-deterministic
    from (session, function-name, kwargs-hash). Real workflows call the
    same tool with the same args multiple times (list_files, get_status,
    repeated lookups, parallel fanout). All such calls get the SAME
    ACS request_id; the Guardian's per-session replay protection
    rejects every call after the first with REPLAY_DETECTED (-32005).
    The user's agent breaks: 'list_files' works on first call, fails
    on every subsequent call in the same session.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _free_port()
        cls.url = f"http://127.0.0.1:{cls.port}/acs"
        cls.server = HTTPServer(("127.0.0.1", cls.port), RecordingGuardian)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        RecordingGuardian.recorded.clear()
        RecordingGuardian.seen_per_session.clear()
        os.environ["ACS_HANDSHAKE"] = "0"

    def _ctx(self, tool_name: str, kwargs: dict):
        from nat.middleware.middleware import (
            InvocationContext, FunctionMiddlewareContext)
        return InvocationContext(
            function_context=FunctionMiddlewareContext(
                name=tool_name, config=None, description=None,
                input_schema=None,
                single_output_schema=type(None),
                stream_output_schema=type(None),
            ),
            original_args=(), original_kwargs=kwargs,
            modified_args=(), modified_kwargs=dict(kwargs),
        )

    def test_repeat_tool_call_does_not_get_replay_detected(self) -> None:
        """Two calls to list_files() within the same session — the SECOND
        call MUST NOT be rejected by Guardian replay protection."""
        cfg = ACSMiddlewareConfig(
            guardian_url=self.url, default_deny=False,
            session_id="repeat-tool-session",
        )
        mw = ACSMiddleware(cfg)

        ctx1 = self._ctx("list_files", {})
        r1 = asyncio.run(mw.pre_invoke(ctx1))
        ctx2 = self._ctx("list_files", {})
        r2 = asyncio.run(mw.pre_invoke(ctx2))

        # Both pre_invoke calls should hit the Guardian
        tool_call_records = [r for r in RecordingGuardian.recorded
                             if r["method"] == "steps/toolCallRequest"]
        self.assertEqual(len(tool_call_records), 2,
            f"expected 2 toolCallRequest sends, got {tool_call_records}")

        # The two requests MUST have different request_ids; otherwise the
        # Guardian's replay protection rejects the second call.
        rid1, rid2 = tool_call_records[0]["request_id"], tool_call_records[1]["request_id"]
        self.assertNotEqual(rid1, rid2,
            "BUG #1: NAT adapter sent the same request_id for two distinct "
            "calls to the same tool with the same args. Guardian replay "
            "protection rejects the second call with REPLAY_DETECTED. "
            "Repeat tool calls in real workflows (list_files, get_status, "
            "etc.) will break in production.")

@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class FailureMode2_GuardianRestartReplayWindow(unittest.TestCase):
    """FAILURE MODE #2: GuardianState is in-process memory only. On
    Guardian restart (deploy, OOM, crash, container roll), the
    seen-request-id set is empty. Every envelope sent before the restart
    is now replayable — the §10.3 MUST is silently disabled.

    Real deployments restart Guardians continuously. This test sends an
    envelope, restarts the Guardian process, re-sends the same envelope,
    and asserts the replay is still rejected.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _free_port()
        cls.url = f"http://127.0.0.1:{cls.port}/acs"
        cls.tmpdir = Path(__file__).resolve().parent / "_guardian_state_tmp"
        cls.tmpdir.mkdir(exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _start_guardian(self):
        env = os.environ.copy()
        env["ACS_DEV_MODE"] = "1"
        env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env["ACS_GUARDIAN_STATE_DIR"] = str(self.tmpdir)  # for the fix
        proc = subprocess.Popen(
            [sys.executable, str(GUARDIAN_SCRIPT), "--port", str(self.port)], env=env,
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
        )
        _wait("127.0.0.1", self.port)
        return proc

    def _send_envelope(self, sid: str, rid: str):
        import urllib.request
        import uuid as _uuid
        from datetime import datetime, timezone
        body = json.dumps({
            "jsonrpc": "2.0", "id": str(_uuid.uuid4()),
            "method": "steps/sessionStart",
            "params": {
                "acs_version": "0.1.0", "request_id": rid,
                "timestamp": datetime.now(timezone.utc)
                    .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "metadata": {"agent_id": "test", "session_id": sid, "platform": "test"},
                "payload": {},
            },
        }).encode()
        req = urllib.request.Request(self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode())

    def test_replay_protection_survives_guardian_restart(self) -> None:
        import uuid as _uuid
        sid = str(_uuid.uuid4())
        rid = str(_uuid.uuid4())

        proc = self._start_guardian()
        try:
            r1 = self._send_envelope(sid, rid)
            self.assertIn("result", r1, "first send must succeed")
        finally:
            proc.terminate()
            try: proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired: proc.kill()

        # Restart Guardian fresh — same port, same data dir if the fix is
        # in place. Without the fix, seen_request_ids is empty.
        proc = self._start_guardian()
        try:
            r2 = self._send_envelope(sid, rid)
            self.assertIn("error", r2,
                "BUG #2: replayed envelope was accepted after Guardian restart. "
                "§10.3 says Guardians MUST reject duplicate request_ids — but "
                "RAM-only state means every restart opens a replay window. "
                "Any deployment with autoscaling, deploys, or crash-restart "
                "loses replay protection on every restart.")
            self.assertEqual(r2["error"]["code"], -32005,
                f"expected REPLAY_DETECTED (-32005), got {r2['error']}")
        finally:
            proc.terminate()
            try: proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired: proc.kill()


@unittest.skipUnless(_NAT_OK, "nvidia-nat-core not installed")
class FailureMode3_LifecycleSubscriptionRace(unittest.TestCase):
    """FAILURE MODE #3: _ensure_lifecycle_subscribed is check-then-set
    with no lock. Two parallel pre_invoke calls (normal in NAT — LLM and
    tool calls overlap) both see _lifecycle_subscribed=False, both
    subscribe. Every subsequent WORKFLOW_START / WORKFLOW_END fires its
    ACS lifecycle hooks TWICE.
    """

    def test_concurrent_subscribe_calls_subscribe_only_once(self) -> None:
        """Force the race window with a slow fake subscribe(); count
        actual calls. Bug = > 1."""
        import acs_adapter as adapter_mod

        subscribe_calls = [0]
        subscribe_lock = threading.Lock()

        class FakeSubscription:
            def unsubscribe(self): pass

        class FakeMgr:
            def subscribe(self, on_next, on_error=None, on_complete=None):
                # Widen the race window — both racing threads sleep
                # inside subscribe(), so the second one cannot find a
                # post-set _lifecycle_subscribed=True flag if there's no
                # mutual exclusion before subscribe was called.
                time.sleep(0.05)
                with subscribe_lock:
                    subscribe_calls[0] += 1
                return FakeSubscription()

        class FakeCtx:
            intermediate_step_manager = FakeMgr()

        cfg = ACSMiddlewareConfig(
            guardian_url="http://127.0.0.1:1/dead",
            default_deny=False, session_id="race-session-3",
        )
        mw = ACSMiddleware(cfg)

        # Patch Context.get() so both threads see our FakeCtx
        import unittest.mock as mock
        with mock.patch.object(adapter_mod, "_NATContext") as patched_ctx:
            patched_ctx.get.return_value = FakeCtx()

            barrier = threading.Barrier(2)
            def runner():
                barrier.wait()  # release both threads simultaneously
                mw._ensure_lifecycle_subscribed()

            t1 = threading.Thread(target=runner)
            t2 = threading.Thread(target=runner)
            t1.start(); t2.start()
            t1.join(); t2.join()

        self.assertEqual(subscribe_calls[0], 1,
            f"BUG #3: lifecycle subscribe() was called {subscribe_calls[0]} "
            f"times instead of 1. Two threads raced through "
            f"_ensure_lifecycle_subscribed's check-then-set with no lock. "
            f"Every subsequent WORKFLOW event will fire its ACS lifecycle "
            f"hook {subscribe_calls[0]} times: duplicate sessionStart, "
            f"duplicate sessionEnd, duplicated audit chain entries.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
