"""
End-to-end test: start the example Guardian, pipe Claude Code-shaped
hook payloads through acs_adapter.py, assert the output Claude Code
would receive.

Schema source: https://code.claude.com/docs/en/hooks
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
ADAPTER = ADAPTER_DIR / "acs_adapter.py"
GUARDIAN = ADAPTER_DIR.parent / "example-guardian" / "example_guardian.py"


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"guardian did not start on {host}:{port}")


def _claude_code_event(name: str, **extra) -> dict:
    """Construct a hook event matching Claude Code's documented schema."""
    base = {
        "session_id": "test-cc-session",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp/work",
        "hook_event_name": name,
    }
    if name in ("PreToolUse", "PostToolUse", "Stop"):
        base["permission_mode"] = "default"
        base["effort"] = {"level": "high"}
    base.update(extra)
    return base


class AdapterRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _find_free_port()
        env = os.environ.copy(); env["ACS_DEV_MODE"] = "1"; env.pop("ACS_HMAC_SECRET", None); env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.guardian_proc = subprocess.Popen(
            [sys.executable, str(GUARDIAN), "--port", str(cls.port)], env=env,
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
        )
        _wait_for_port("127.0.0.1", cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()

    def _run_adapter(
        self,
        event: dict,
        env_overrides: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        env = os.environ.copy()
        env["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{self.port}/acs"
        if env_overrides:
            env.update(env_overrides)
        proc = subprocess.run(
            [sys.executable, str(ADAPTER)],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    # ----- PreToolUse: allow path (must produce hookSpecificOutput.permissionDecision=allow) -----

    def test_safe_tool_call_allows(self) -> None:
        rc, out, err = self._run_adapter(_claude_code_event(
            "PreToolUse", tool_name="Read", tool_input={"file_path": "/tmp/safe.txt"},
        ))
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "allow")

    def test_safe_bash_allows(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "PreToolUse", tool_name="Bash", tool_input={"command": "ls -la"},
        ))
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "allow")

    # ----- PreToolUse: deny path -----

    def test_destructive_bash_denied(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "PreToolUse", tool_name="Bash", tool_input={"command": "rm -rf /home/user"},
        ))
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        hso = payload["hookSpecificOutput"]
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("destructive", hso["permissionDecisionReason"].lower())

    def test_write_to_protected_path_denied(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "PreToolUse", tool_name="Write",
            tool_input={"file_path": "/etc/passwd", "content": "x"},
        ))
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("protected", payload["hookSpecificOutput"]["permissionDecisionReason"].lower())

    # ----- Lifecycle hooks: empty stdout = proceed -----

    def test_session_start_no_output(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "SessionStart", source="startup", model="claude-opus-4-7",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_session_end_no_output(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "SessionEnd", reason="clear",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_user_prompt_submit_no_block(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "UserPromptSubmit", prompt="summarize my emails",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_post_tool_use_no_block(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "PostToolUse", tool_name="Read",
            tool_input={"file_path": "/tmp/x"}, tool_output="file contents",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_notification_no_block(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "Notification", notification_type="permission_prompt",
            message="confirm action",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    # ----- Unknown hook proceeds silently -----

    def test_unmapped_hook_proceeds(self) -> None:
        rc, out, _ = self._run_adapter({
            "hook_event_name": "SomeFutureHook",
            "session_id": "x",
            "cwd": "/tmp",
            "transcript_path": "/tmp/t",
            "data": {"x": 1},
        })
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    # ----- Fail posture -----

    def test_guardian_unreachable_default_deny_pretoolue(self) -> None:
        """PreToolUse with Guardian down + DEFAULT_DENY=1: emit deny in PreToolUse output shape."""
        rc, out, err = self._run_adapter(
            _claude_code_event(
                "PreToolUse", tool_name="Read",
                tool_input={"file_path": "/tmp/x"},
            ),
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           "ACS_DEFAULT_DENY": "1",
                           "ACS_HANDSHAKE": "0"},
        )
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("decision-failure", payload["hookSpecificOutput"]["permissionDecisionReason"].lower())
        # §6.4: every decision-failure path must produce an audit event
        self.assertIn("ACS_AUDIT", err)
        self.assertIn("decision_failure_fail_closed", err)

    def test_guardian_unreachable_default_deny_posttool(self) -> None:
        """PostToolUse with Guardian down + DEFAULT_DENY=1: top-level decision: block."""
        rc, out, err = self._run_adapter(
            _claude_code_event(
                "PostToolUse", tool_name="Read",
                tool_input={"file_path": "/tmp/x"}, tool_output="x",
            ),
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           "ACS_DEFAULT_DENY": "1",
                           "ACS_HANDSHAKE": "0"},
        )
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["decision"], "block")
        self.assertIn("decision-failure", payload["reason"].lower())
        self.assertIn("ACS_AUDIT", err)

    def test_guardian_unreachable_fail_open_default_is_audit(self) -> None:
        """Spec default per §6.4: fail-open, every bypass recorded as an audit event."""
        rc, out, err = self._run_adapter(
            _claude_code_event(
                "PreToolUse", tool_name="Read",
                tool_input={"file_path": "/tmp/x"},
            ),
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           "ACS_HANDSHAKE": "0"},
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "")  # proceed (fail-open)
        # §6.4: 'Every step that proceeds without a decision MUST be recorded as an audit event'
        self.assertIn("ACS_AUDIT", err, "fail-open MUST emit an audit event per §6.4")
        self.assertIn("fail_open_bypass", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
