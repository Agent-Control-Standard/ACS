"""
End-to-end tests for the Cursor adapter, using the Claude Code example
Guardian. Cursor's hook schema is taken from the create-hook skill that
ships with Cursor.

Live verification status: unit-tested only. Cursor is a desktop app
that does not have a documented headless mode equivalent to Claude
Code's `--print`, so a live fire-through from Cursor is left as a
manual verification step for a reviewer with Cursor installed.
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
ADAPTER = ADAPTER_DIR / "cursor_adapter.py"
# Shared example Guardian (same ACS shape across all adapters)
GUARDIAN = ADAPTER_DIR.parent / "example-guardian" / "example_guardian.py"


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"guardian did not start on {host}:{port}")


class CursorAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _find_free_port()
        cls.guardian_proc = subprocess.Popen(
            [sys.executable, str(GUARDIAN), "--port", str(cls.port)],
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
        )
        _wait("127.0.0.1", cls.port)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()

    def _run(self, event_name: str, event: dict, env_overrides: dict | None = None) -> tuple[int, str, str]:
        env = os.environ.copy()
        env["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{self.port}/acs"
        if env_overrides:
            env.update(env_overrides)
        proc = subprocess.run(
            [sys.executable, str(ADAPTER), event_name],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    # ----- preToolUse: allow path -----
    def test_pre_tool_safe_read_allows(self) -> None:
        rc, out, err = self._run("preToolUse", {
            "session_id": "cur-1", "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/x"},
        })
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["permission"], "allow")

    def test_pre_tool_safe_bash_allows(self) -> None:
        rc, out, _ = self._run("preToolUse", {
            "session_id": "cur-2", "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["permission"], "allow")

    # ----- preToolUse: deny path -----
    def test_pre_tool_destructive_bash_denies(self) -> None:
        rc, out, _ = self._run("preToolUse", {
            "session_id": "cur-3", "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /home/user"},
        })
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["permission"], "deny")
        self.assertIn("destructive", payload["user_message"].lower())

    def test_pre_tool_write_to_protected_path_denies(self) -> None:
        rc, out, _ = self._run("preToolUse", {
            "session_id": "cur-4", "tool_name": "Write",
            "tool_input": {"file_path": "/etc/passwd", "content": "x"},
        })
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["permission"], "deny")

    # ----- beforeShellExecution -----
    def test_before_shell_safe(self) -> None:
        rc, out, _ = self._run("beforeShellExecution", {
            "session_id": "cur-5", "command": "ls",
        })
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["permission"], "allow")

    def test_before_shell_destructive_denies(self) -> None:
        rc, out, _ = self._run("beforeShellExecution", {
            "session_id": "cur-6", "command": "rm -rf /home/x",
        })
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["permission"], "deny")

    # ----- subagentStart -----
    def test_subagent_start_allow(self) -> None:
        rc, out, _ = self._run("subagentStart", {
            "session_id": "cur-7", "subagent_type": "explore",
        })
        self.assertEqual(rc, 0)
        # session start variant on the Guardian -> allow; subagentStart maps to subagentStart
        payload = json.loads(out) if out else {}
        self.assertEqual(payload.get("permission"), "allow")

    # ----- Lifecycle events: empty output -----
    def test_session_start_silent(self) -> None:
        rc, out, _ = self._run("sessionStart", {"session_id": "cur-8"})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_after_agent_response_silent(self) -> None:
        rc, out, _ = self._run("afterAgentResponse", {
            "session_id": "cur-9", "response": "ok"})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    # ----- Unknown event -----
    def test_unmapped_event_silent(self) -> None:
        rc, out, _ = self._run("someFutureCursorEvent", {"session_id": "x"})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    # ----- Fail posture -----
    def test_guardian_unreachable_default_deny_on_permission_event(self) -> None:
        rc, out, _ = self._run("preToolUse",
            {"session_id": "cur-10", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}},
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead"},
        )
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["permission"], "deny")
        self.assertIn("unreachable", payload["user_message"].lower())

    def test_guardian_unreachable_fail_open(self) -> None:
        rc, out, _ = self._run("preToolUse",
            {"session_id": "cur-11", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}},
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           "ACS_DEFAULT_DENY": "0"},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_before_submit_prompt_block_via_exit_code(self) -> None:
        """beforeSubmitPrompt blocks via exit code 2, not stdout."""
        # Synthesize a deny by routing through Guardian with a payload it
        # treats as unknown method (which the example Guardian denies).
        # Easier: pretend the Guardian is unreachable; default-deny posture
        # for beforeSubmitPrompt should exit 2.
        rc, _, err = self._run("beforeSubmitPrompt",
            {"session_id": "cur-12", "prompt": "anything"},
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead"},
        )
        self.assertEqual(rc, 2)
        self.assertIn("prompt blocked", err.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
