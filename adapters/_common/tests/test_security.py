"""
Security tests for the shared `acs_common` helpers and the Guardian
HTTP path. Each test names a specific attack and asserts the
mitigation that defeats it.

Spec context: ACS is a security project (the whole point is to police
agent behavior). Adapter and Guardian code that itself has security
holes undermines the standard. These tests are the falsifiers for the
mitigations documented in `adapters/SECURITY.md`.
"""
from __future__ import annotations

import binascii
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import acs_common  # noqa: E402
from test_harness import free_port as _free_port, wait_port as _wait  # noqa: E402


HERE = Path(__file__).resolve().parent
GUARDIAN = HERE.parent.parent / "example-guardian" / "example_guardian.py"


# ----- 1. SSRF via Guardian URL -----

class GuardianUrlSchemeAllowlist(unittest.TestCase):
    """ACS_GUARDIAN_URL must be http/https; file://, ftp://, data://,
    etc. must be refused before the adapter calls urlopen — otherwise
    an attacker who controls the env var can read arbitrary files."""

    def test_file_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError) as cm:
            acs_common.validate_guardian_url("file:///etc/passwd")
        self.assertIn("scheme", str(cm.exception).lower())

    def test_ftp_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            acs_common.validate_guardian_url("ftp://example.com/x")

    def test_data_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            acs_common.validate_guardian_url("data:text/plain,evil")

    def test_javascript_scheme_rejected(self) -> None:
        with self.assertRaises(ValueError):
            acs_common.validate_guardian_url("javascript:alert(1)")

    def test_http_accepted(self) -> None:
        acs_common.validate_guardian_url("http://127.0.0.1:8787/acs")  # no raise

    def test_https_accepted(self) -> None:
        acs_common.validate_guardian_url("https://guardian.internal/acs")


# ----- 2. World-readable secret file -----

class HmacSecretFilePermissions(unittest.TestCase):
    """A secret file readable by group or world is a configuration mistake
    that must be refused — silently using a world-readable secret leaks
    the HMAC key to any local process."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.secret_path = Path(self.tmpdir) / "hmac.key"
        self.secret_path.write_bytes(b"super-secret-key-material" * 4)
        self._old_env = {
            "ACS_HMAC_SECRET_FILE": os.environ.get("ACS_HMAC_SECRET_FILE"),
            "ACS_HMAC_SECRET": os.environ.get("ACS_HMAC_SECRET"),
        }
        os.environ["ACS_HMAC_SECRET_FILE"] = str(self.secret_path)
        os.environ.pop("ACS_HMAC_SECRET", None)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_mode_0600_accepted(self) -> None:
        os.chmod(self.secret_path, 0o600)
        # Returns secret bytes; no raise
        self.assertTrue(acs_common.load_hmac_secret().startswith(b"super-secret"))

    def test_world_readable_rejected(self) -> None:
        os.chmod(self.secret_path, 0o644)
        with self.assertRaises(acs_common.SecretFilePermissionsError):
            acs_common.load_hmac_secret()

    def test_group_readable_rejected(self) -> None:
        os.chmod(self.secret_path, 0o640)
        with self.assertRaises(acs_common.SecretFilePermissionsError):
            acs_common.load_hmac_secret()

    def test_symlink_rejected(self) -> None:
        real = Path(self.tmpdir) / "real.key"
        real.write_bytes(b"x" * 32)
        os.chmod(real, 0o600)
        self.secret_path.unlink()
        os.symlink(real, self.secret_path)
        with self.assertRaises(acs_common.SecretFilePermissionsError):
            acs_common.load_hmac_secret()


# ----- 3. Guardian HTTP DoS via oversized body -----

class GuardianBodySizeCap(unittest.TestCase):
    """A POST with Content-Length > limit must be refused without reading
    the whole body. The Guardian's documented max_payload_size_bytes in
    the handshake is 1 MiB; the read path must enforce it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _free_port()
        env = os.environ.copy()
        env["ACS_DEV_MODE"] = "1"
        env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.proc = subprocess.Popen(
            [sys.executable, str(GUARDIAN), "--port", str(cls.port)], env=env,
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
        )
        _wait("127.0.0.1", cls.port)
        cls.url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def test_oversized_request_rejected(self) -> None:
        oversized = b"a" * (2 * 1024 * 1024)  # 2 MiB > 1 MiB cap
        req = urllib.request.Request(
            self.url, data=oversized,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        code = None
        connection_reset = False
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        except urllib.error.URLError:
            # The Guardian sent its 413 response and closed the socket
            # before the client finished writing 2 MiB — manifests as a
            # connection reset / write error on the client side. That's
            # still a successful rejection: the body was never accepted.
            connection_reset = True
        # Any outcome that is NOT 200 OK proves the body was refused.
        self.assertFalse(code == 200,
            f"oversized request was accepted (status {code}) — DoS risk")
        if not connection_reset:
            self.assertIn(code, (400, 413),
                f"expected 413 Payload Too Large or 400 or connection reset; got {code}")


# ----- 4. Cache directory permissions -----

class CacheDirPermissions(unittest.TestCase):
    """save_session_state and the handshake cache must create files with
    mode 0600 and parent dirs with mode 0700 — otherwise a local
    attacker can read or poison adapter state."""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp())
        self._old = os.environ.get("ACS_SESSION_STATE_DIR")
        os.environ["ACS_SESSION_STATE_DIR"] = str(self.tmpdir / "state")
        # Re-evaluate module-level dir
        import importlib
        importlib.reload(acs_common)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        if self._old is None:
            os.environ.pop("ACS_SESSION_STATE_DIR", None)
        else:
            os.environ["ACS_SESSION_STATE_DIR"] = self._old

    def test_session_state_file_is_0600(self) -> None:
        acs_common.save_session_state("test-session", {"x": 1})
        path = acs_common._session_state_path("test-session")
        self.assertTrue(path.exists())
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600,
            f"session-state file mode is {oct(mode)}, want 0o600")

    def test_session_state_dir_is_0700(self) -> None:
        acs_common.save_session_state("test-session", {"x": 1})
        d = acs_common._SESSION_STATE_DIR
        mode = stat.S_IMODE(os.stat(d).st_mode)
        self.assertEqual(mode, 0o700,
            f"session-state dir mode is {oct(mode)}, want 0o700")


# ----- 5. Regex DoS / oversized command input -----

class RegexInputSizeCap(unittest.TestCase):
    """Destructive-bash regex must not run on arbitrarily-large inputs.
    A multi-MB command crafted to trigger backtracking would freeze the
    Guardian; cap input length and audit the skip."""

    def test_oversized_command_is_short_circuited(self) -> None:
        # Construct a 64 KiB command that is benign but oversized
        large_cmd = "echo " + ("a" * (64 * 1024))
        # The destructive matcher should refuse to scan and return a
        # sentinel that the caller treats as "do not allow without
        # external review", not a False that allows the command.
        result = acs_common.scan_destructive_bash_safely(large_cmd, max_len=8192)
        self.assertEqual(result, "input_too_large",
            "oversized command MUST be flagged, not scanned, not silently allowed")

    def test_small_destructive_command_still_caught(self) -> None:
        # Use the Guardian's actual pattern set
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "example-guardian"))
        import example_guardian
        for pat in example_guardian.DESTRUCTIVE_BASH_PATTERNS:
            if pat.search("rm -rf /home/x"):
                return
        self.fail("destructive pattern matching broken")

    def test_small_safe_command_returns_none(self) -> None:
        self.assertIsNone(
            acs_common.scan_destructive_bash_safely("ls -la", max_len=8192))


class Item13_DestructiveRmFlagVariants(unittest.TestCase):
    """Regression: every `rm` variant that combines recursive + force,
    no matter what other harmless flags are present (verbose, interactive,
    etc.), MUST be caught.

    Original Guardian regex used `\\b` after a fixed `-rf` match, so
    `rm -rfv /tmp/...` slipped through — the trailing `v` defeated the
    word boundary. A trivial single-letter extension defeating the
    policy is the worst class of regex bug for a security control."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "example-guardian"))
        import example_guardian
        cls.eg = example_guardian

    def _assert_caught(self, cmd: str) -> None:
        match = self.eg._matches_destructive_bash(cmd)
        self.assertTrue(match,
            f"REGRESSION: destructive command not caught: {cmd!r}. "
            f"The Guardian's regex must match rm with recursive+force "
            f"flags regardless of additional harmless flags.")

    def _assert_allowed(self, cmd: str) -> None:
        match = self.eg._matches_destructive_bash(cmd)
        self.assertFalse(match,
            f"FALSE POSITIVE: benign command flagged as destructive: {cmd!r}")

    def test_rf_variants_caught(self) -> None:
        # Canonical
        self._assert_caught("rm -rf /home/x")
        self._assert_caught("rm -fr /home/x")
        self._assert_caught("rm --recursive --force /home/x")
        self._assert_caught("rm --force --recursive /home/x")

    def test_rf_with_trailing_letters_caught(self) -> None:
        # The bug Bar found: extra flag letters after r/f defeated the regex
        self._assert_caught("rm -rfv /home/x")
        self._assert_caught("rm -rfvi /home/x")
        self._assert_caught("rm -rfvI /home/x")
        self._assert_caught("rm -frv /home/x")

    def test_rf_with_middle_or_leading_letters_caught(self) -> None:
        self._assert_caught("rm -rvf /home/x")
        self._assert_caught("rm -vrf /home/x")
        self._assert_caught("rm -ivrf /home/x")

    def test_rf_with_trailing_slash_and_command_chain_caught(self) -> None:
        # Exact shape that Claude generated when Bar asked for an -rf test
        self._assert_caught("rm -rfv /tmp/this-is-a-fake-test-path-12345/")
        self._assert_caught("rm -rfv /tmp/foo/ ; echo done")

    def test_benign_rm_not_flagged(self) -> None:
        # rm WITHOUT both r and f is allowed
        self._assert_allowed("rm -v /home/x")
        self._assert_allowed("rm -i /home/x")
        self._assert_allowed("rm /home/x")
        self._assert_allowed("rmdir /home/x")
        # NOTE: `echo rm -rf /home/x` IS flagged by the regex (conservative
        # by design — wrapping a destructive command in `echo` and piping
        # to `sh` is a known evasion). Operators who want to allow it
        # disable the pattern in their policy bundle.


class Item14_ToolNameCaseInsensitive(unittest.TestCase):
    """Regression: the example Guardian's destructive-Bash policy was
    gated on `tool_name in ("Bash", "Shell")` — a case-sensitive string
    match. A NAT YAML key `shell` (lowercase) became the instance name,
    sailed past the check, and a real LLM-driven `rm -rf` against a
    sandbox directory ran to completion with the canary file deleted.
    The destructive regex was correct; the OUTER guard was too strict.

    Every reasonable shell tool name spelling MUST hit the same policy
    branch:
      - "Bash" (Claude Code adapter's PreToolUse tool name)
      - "Shell" (Cursor's beforeShellExecution synthesizes this name)
      - "shell" (NAT YAML key used as instance_name)
      - "bash" / "BASH" (paranoia — any caller-chosen casing)
    """

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "example-guardian"))
        import example_guardian
        cls.eg = example_guardian

    def _call(self, tool_name: str, command: str) -> dict:
        params = {
            "request_id": "00000000-0000-4000-8000-000000000001",
            "chain_hash": "0" * 64,
            "metadata": {"session_id": "00000000-0000-4000-8000-000000000002"},
            "payload": {
                "tool": {"name": tool_name},
                "arguments": {"command": {"value": command}},
            },
        }
        return self.eg.evaluate_step(
            "steps/toolCallRequest", params,
            "00000000-0000-4000-8000-000000000001", "0" * 64)

    def test_lowercase_shell_destructive_denied(self) -> None:
        """The exact regression: tool name 'shell' (lowercase) MUST hit
        the destructive policy branch — discovered when a real Vertex-
        driven react_agent's `shell` tool ran `rm -rf` and Guardian
        allowed."""
        result = self._call("shell", "rm -rf /tmp/x/")
        self.assertEqual(result.get("decision"), "deny",
            "REGRESSION: lowercase 'shell' tool with rm -rf MUST be denied; "
            "the case-sensitive name check let real destructive commands through")
        self.assertIn("destructive_command", result.get("reason_codes", []))

    def test_every_reasonable_casing_denied(self) -> None:
        for name in ("Bash", "BASH", "bash", "Shell", "SHELL", "shell", "ShElL"):
            with self.subTest(tool_name=name):
                result = self._call(name, "rm -rf /tmp/x/")
                self.assertEqual(result.get("decision"), "deny",
                    f"tool name {name!r} should hit destructive-Bash branch")
                self.assertIn("destructive_command",
                                result.get("reason_codes", []))

    def test_unrelated_tool_unaffected(self) -> None:
        """Case-folding must not over-broaden — `read` is not a shell tool."""
        result = self._call("Read", "rm -rf /tmp/x/")
        # Read tool with a 'command' arg that LOOKS dangerous — not a
        # shell call, the destructive regex isn't applied here.
        self.assertEqual(result.get("decision"), "allow",
            "case-fold must not pull non-shell tools into shell policy")

    def test_task_subagent_gate_also_case_insensitive(self) -> None:
        """The Task tool deny was also case-sensitive; same case-fold."""
        # ALLOW_SUBAGENT defaults False so Task should be denied
        for name in ("Task", "task", "TASK"):
            with self.subTest(tool_name=name):
                result = self._call(name, "")
                self.assertEqual(result.get("decision"), "deny",
                    f"tool name {name!r} (Task variant) must hit subagent gate")
                self.assertIn("subagent_gated", result.get("reason_codes", []))


class Item15_VerifySignatureRobustToMalformedBase64(unittest.TestCase):
    """Regression: verify_signature() called base64.b64decode() directly
    without exception handling. A malformed signature value (truncation,
    garbage characters, wrong padding) raised binascii.Error / ValueError
    up to the request path instead of producing the spec's SIGNATURE_INVALID
    (-32004) response. The Guardian only caught GuardianError around
    signature checks, so the uncaught binascii.Error tore down the request
    on the wire as a 500 / disconnected handler — security control
    converted to a denial-of-service vector.

    Every form of unparseable base64 MUST return False (signature invalid),
    never crash."""

    BAD_VALUES = [
        "not-base64",                # raw garbage
        "this is not!base64@@@",     # non-base64 characters
        "!!!",                        # too short, illegal chars
        "===",                        # padding only
        "AB==CD",                    # padding mid-string
        "A" * 1000003,               # huge, no padding alignment
        "",                           # empty (this is "no signature" → False, no crash)
    ]

    def _make_envelope(self, sig_value):
        return {
            "params": {
                "request_id": "00000000-0000-4000-8000-000000000001",
                "metadata": {"session_id": "00000000-0000-4000-8000-000000000002"},
                "signature": {"algorithm": "HMAC-SHA256", "value": sig_value},
            }
        }

    def test_malformed_signature_returns_false_not_crashes(self) -> None:
        import os
        os.environ["ACS_HMAC_SECRET"] = "verify-sig-robustness-test-secret"
        try:
            for bad in self.BAD_VALUES:
                with self.subTest(signature=bad[:30]):
                    env = self._make_envelope(bad)
                    try:
                        result = acs_common.verify_signature(env)
                    except (binascii.Error, ValueError, TypeError) as e:
                        self.fail(
                            f"REGRESSION: malformed signature {bad[:30]!r} "
                            f"raised {type(e).__name__} instead of returning "
                            f"False; this turns SIGNATURE_INVALID into a "
                            f"crash on the request path")
                    self.assertFalse(
                        result,
                        f"malformed signature {bad[:30]!r} must verify as False")
        finally:
            os.environ.pop("ACS_HMAC_SECRET", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
