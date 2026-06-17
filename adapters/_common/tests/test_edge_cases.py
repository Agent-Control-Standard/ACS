"""
Cross-cutting edge-case tests for the 12 items from the post-PR audit.

Each test names the item, exercises the failure scenario, and asserts
the fix-side behavior. Tests are written first; fixes follow.
"""
from __future__ import annotations

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
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import acs_common  # noqa: E402

HERE = Path(__file__).resolve().parent
GUARDIAN = HERE.parent.parent / "example-guardian" / "example_guardian.py"


def _free_port() -> int:
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
    raise RuntimeError(f"server not up on {host}:{port}")


# ===== #1: rfc8785 cross-install JCS consistency =====

class Item01_JcsConsistency(unittest.TestCase):
    """The fallback `jcs_canonicalize` and the rfc8785 package must
    produce identical bytes for every shape ACS envelopes carry. If
    they differ, a deployment with rfc8785 on one side and not the
    other gets signature-verification failures on every request."""

    SAMPLES = [
        # Typical PreToolUse envelope
        {"jsonrpc": "2.0", "id": "abc", "method": "steps/toolCallRequest",
         "params": {"acs_version": "0.1.0", "request_id": "11111111-1111-4111-8111-111111111111",
                    "timestamp": "2026-06-17T12:00:00.000Z",
                    "metadata": {"agent_id": "x", "session_id": "11111111-1111-4111-8111-111111111111"},
                    "payload": {"tool": {"name": "Bash"},
                                "arguments": {"command": {"value": "ls -la"}}}}},
        # Empty object, empty array, null
        {"a": {}, "b": [], "c": None, "d": True, "e": False},
        # Integers + negatives + zero
        {"x": 0, "y": -1, "z": 123456789, "neg": -987654321},
        # Nested + ordered-keys check
        {"z": 1, "a": 2, "m": {"y": [3, 1, 2], "x": "hi"}},
        # Unicode (BMP)
        {"emoji": "🚀", "hebrew": "שלום", "ascii": "hi"},
    ]

    def test_fallback_matches_rfc8785_on_acs_envelope_shapes(self) -> None:
        try:
            import rfc8785
        except ImportError:
            self.skipTest("rfc8785 not installed; can't compare")
        for sample in self.SAMPLES:
            fallback = json.dumps(sample, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8")
            canonical = rfc8785.dumps(sample)
            self.assertEqual(fallback, canonical,
                f"JCS divergence between fallback and rfc8785 on {sample!r}:\n"
                f"  fallback : {fallback!r}\n"
                f"  rfc8785  : {canonical!r}\n"
                "A deployment with mismatched JCS implementations would "
                "fail every signed-envelope verification.")


# ===== #2: Guardian regex DoS — server-side input cap =====

class Item02_GuardianRegexInputCap(unittest.TestCase):
    """The Guardian's destructive-bash regex must NOT scan arbitrarily-
    large inputs. _common has scan_destructive_bash_safely with an 8KB
    cap, but the Guardian's own code path was iterating patterns
    directly — uncapped."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _free_port()
        env = os.environ.copy()
        env["ACS_DEV_MODE"] = "1"
        env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        # Use a unique state dir per run to avoid leftover replay state
        cls.statedir = tempfile.mkdtemp(prefix="acs-guardian-state-")
        env["ACS_GUARDIAN_STATE_DIR"] = cls.statedir
        cls.proc = subprocess.Popen(
            [sys.executable, str(GUARDIAN), "--port", str(cls.port)], env=env,
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
        )
        _wait("127.0.0.1", cls.port)
        cls.url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proc.terminate()
        try: cls.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired: cls.proc.kill()
        import shutil
        shutil.rmtree(cls.statedir, ignore_errors=True)

    def test_huge_bash_command_is_capped_not_scanned(self) -> None:
        """A 100 KiB bash command MUST not pin the Guardian on regex
        backtracking. The Guardian denies it with a clear reason; does
        NOT iterate the destructive-bash patterns over the full input."""
        # 500 KiB command; would burn CPU on naive regex matching
        huge = "a " * (250 * 1024)
        body = json.dumps({
            "jsonrpc": "2.0", "id": "ed1",
            "method": "steps/toolCallRequest",
            "params": {
                "acs_version": "0.1.0",
                "request_id": str(uuid.uuid4()),
                "timestamp": acs_common.iso8601_now(),
                "metadata": {"agent_id": "t", "session_id": str(uuid.uuid4())},
                "payload": {"tool": {"name": "Bash"},
                            "arguments": {"command": {"value": huge}}},
            },
        }).encode()
        # Send under a strict time bound
        req = urllib.request.Request(self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        start = time.monotonic()
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            elapsed = time.monotonic() - start
            data = json.loads(resp.read().decode())
        self.assertLess(elapsed, 1.0,
            f"Guardian took {elapsed:.2f}s to handle a 500 KiB command — "
            f"regex DoS gap not closed server-side")
        # The Guardian should DENY the request rather than allow it
        # (uncapped scan would have produced "allow" since `aaaaaa...`
        # doesn't match destructive-bash patterns).
        result = data.get("result", {})
        self.assertEqual(result.get("decision"), "deny",
            f"Guardian must deny oversized bash command (cannot safely scan); "
            f"got decision={result.get('decision')!r}, full={data}")


# ===== #4: TTL eviction on seen_request_ids =====

class Item04_ReplaySetTtlEviction(unittest.TestCase):
    """seen_request_ids must be bounded. Without eviction, a long-running
    session accumulates UUIDs forever — memory leak + bloated state file."""

    def test_eviction_drops_entries_older_than_2x_skew_window(self) -> None:
        sys.path.insert(0, str(GUARDIAN.parent))
        import example_guardian
        sys.path.insert(0, str(GUARDIAN.parent.parent / "_common"))
        # Create a fresh SessionState for this test
        sid = f"ttl-test-{uuid.uuid4()}"
        # Patch the state dir so this test doesn't pollute home
        with tempfile.TemporaryDirectory() as tmp:
            example_guardian.STATE_DIR = Path(tmp)
            example_guardian.PERSIST_ENABLED = True
            st = example_guardian.SessionState(session_id=sid)
            # Inject an old request_id directly
            old_ts = time.time() - (example_guardian.SKEW_WINDOW_MS / 1000) * 3
            recent_ts = time.time()
            with st.lock:
                # The fix wraps seen_request_ids as a dict of rid -> timestamp
                # (or maintains an ordered structure with timestamps)
                st.seen_request_ids = {} if isinstance(st.seen_request_ids, dict) else st.seen_request_ids
                # If still a set, test fails the fix expectation
                self.assertIsInstance(st.seen_request_ids, dict,
                    "FIX REQUIRED: seen_request_ids must become a dict "
                    "(request_id -> timestamp_seconds) so TTL eviction "
                    "can drop entries older than 2 × skew_window.")
                st.seen_request_ids["old-rid"] = old_ts
                st.seen_request_ids["new-rid"] = recent_ts
                example_guardian.evict_old_request_ids(st)
                self.assertNotIn("old-rid", st.seen_request_ids,
                    "old request_id not evicted")
                self.assertIn("new-rid", st.seen_request_ids,
                    "recent request_id wrongly evicted")


# ===== #5: handshake cache TTL =====

class Item05_HandshakeCacheTtl(unittest.TestCase):
    """Handshake cache must invalidate after a TTL. Operator config
    changes (skew window, profiles) MUST not be served from stale cache."""

    def test_fresh_cache_is_honored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["ACS_HANDSHAKE_CACHE"] = tmp
            import importlib
            importlib.reload(acs_common)
            url = "http://127.0.0.1:1/dead"
            fake_hello = {"negotiated_version": "0.1.0", "_synthetic": True}
            cache_path = acs_common._handshake_cache_path("sess1", url)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(fake_hello))
            # Recently-mtimed cache must be honored
            result = acs_common.do_handshake(
                guardian_url=url, session_id="sess1",
                agent_id="x", platform="t", methods_implemented=[],
            )
            self.assertEqual(result, fake_hello,
                "fresh handshake cache must be honored to avoid the "
                "per-process re-handshake overhead")

    def test_stale_cache_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["ACS_HANDSHAKE_CACHE"] = tmp
            import importlib
            importlib.reload(acs_common)
            url = "http://127.0.0.1:1/dead"
            cache_path = acs_common._handshake_cache_path("sess2", url)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps({"_synthetic": True}))
            # Backdate the cache file 2 hours
            two_hours_ago = time.time() - 2 * 3600
            os.utime(cache_path, (two_hours_ago, two_hours_ago))
            result = acs_common.do_handshake(
                guardian_url=url, session_id="sess2",
                agent_id="x", platform="t", methods_implemented=[],
            )
            # Cache stale → not honored → handshake attempted → fails (dead URL) → None
            self.assertIsNone(result,
                "stale handshake cache was honored — operator Guardian-config "
                "changes would not propagate within the TTL")


# ===== #6: NAT id(context) collision — WeakKeyDictionary =====

class Item06_NatContextIdCollision(unittest.TestCase):
    """When pre_invoke can't set an attr on context (frozen / weird type),
    the fallback used uuid5(id(context)) — and Python recycles ids after
    GC. Two distinct contexts could get the same uuid → collision."""

    def test_distinct_frozen_contexts_get_distinct_uuids(self) -> None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "nat"))
        try:
            import acs_adapter as nat_adapter
        except ImportError:
            self.skipTest("NAT adapter not importable in this env")

        class _StubConfig:
            guardian_url = "http://127.0.0.1:8787/acs"
            default_deny = False
            session_id = "frozen-test"
            timeout_s = 5.0
            target_function_or_group = "x"
            target_location = "input"

        class FrozenContext:
            """Mimics a NAT context that rejects attribute assignment."""
            __slots__ = ("function_context", "modified_kwargs")
            def __init__(self):
                class FC: name = "tool"
                self.function_context = FC()
                self.modified_kwargs = {}

        mw = nat_adapter.ACSMiddleware(_StubConfig())

        ctx1 = FrozenContext()
        rid1 = mw._correlation_request_id(ctx1)
        # Free ctx1, let Python recycle the id
        del ctx1
        import gc; gc.collect()
        ctx2 = FrozenContext()
        rid2 = mw._correlation_request_id(ctx2)
        self.assertNotEqual(rid1, rid2,
            f"FIX REQUIRED: two distinct (frozen) contexts produced the "
            f"same request_id ({rid1}). id(ctx) recycles after GC; the "
            f"frozen-context fallback must use a per-instance unique key "
            f"(WeakKeyDictionary).")


# ===== #7: unicode / null / surrogate round-trip =====

class Item07_UnicodeRoundTrip(unittest.TestCase):
    """Tool args with unicode, NULL bytes, and (where possible) lone
    surrogates must sign+verify cleanly — otherwise emoji-heavy or
    binary-ish args break the wire."""

    def _make_envelope(self, value):
        return {
            "jsonrpc": "2.0", "id": "u1", "method": "steps/toolCallRequest",
            "params": {
                "acs_version": "0.1.0",
                "request_id": "00000000-0000-4000-8000-000000000001",
                "timestamp": "2026-06-17T12:00:00.000Z",
                "metadata": {"agent_id": "x", "session_id": "00000000-0000-4000-8000-000000000001"},
                "payload": {"tool": {"name": "Bash"},
                            "arguments": {"v": {"value": value}}},
            },
        }

    def test_emoji_round_trip(self) -> None:
        env = self._make_envelope("🚀 from agent — ✨")
        key = acs_common.derive_session_key(b"test-secret", "sess")
        acs_common.sign_envelope(env, key=key, session_id="sess")
        self.assertTrue(acs_common.verify_signature(env, key=key, session_id="sess"))

    def test_null_byte_round_trip(self) -> None:
        env = self._make_envelope("before\x00after")
        key = acs_common.derive_session_key(b"test-secret", "sess")
        acs_common.sign_envelope(env, key=key, session_id="sess")
        self.assertTrue(acs_common.verify_signature(env, key=key, session_id="sess"))

    def test_bmp_and_supplementary_planes_round_trip(self) -> None:
        # Hebrew (BMP) + emoji (supplementary plane)
        env = self._make_envelope("שלום 🌍 こんにちは")
        key = acs_common.derive_session_key(b"test-secret", "sess")
        acs_common.sign_envelope(env, key=key, session_id="sess")
        self.assertTrue(acs_common.verify_signature(env, key=key, session_id="sess"))


# ===== #8: ISO 8601 parse resilience =====

class Item08_Iso8601Parse(unittest.TestCase):
    """parse_iso8601 must accept the spec's range of timestamp shapes
    without raising. Brittleness here surfaces as TIMESTAMP_OUT_OF_WINDOW
    on legitimate requests."""

    GOOD = [
        "2026-06-17T12:00:00Z",
        "2026-06-17T12:00:00.000Z",
        "2026-06-17T12:00:00.123456Z",
        "2026-06-17T12:00:00+00:00",
        "2026-06-17T12:00:00.500+02:00",
        "2026-06-17T12:00:00-05:30",
    ]
    BAD = [
        "not a timestamp",
        "2026/06/17 12:00:00",
        "",
    ]

    def test_good_timestamps_parse(self) -> None:
        for ts in self.GOOD:
            try:
                acs_common.parse_iso8601(ts)
            except Exception as e:
                self.fail(f"valid timestamp {ts!r} failed to parse: {e}")

    def test_bad_timestamps_raise_value_error(self) -> None:
        for ts in self.BAD:
            with self.assertRaises((ValueError, AttributeError),
                                   msg=f"{ts!r} should be rejected"):
                acs_common.parse_iso8601(ts)


# ===== #9: ACS_GUARDIAN_HOST_ALLOWLIST =====

class Item09_HostAllowlist(unittest.TestCase):
    """validate_guardian_url should honor an optional
    ACS_GUARDIAN_HOST_ALLOWLIST (comma-separated hostnames) so an
    operator can restrict the env-var attack surface."""

    def setUp(self) -> None:
        self._old = os.environ.get("ACS_GUARDIAN_HOST_ALLOWLIST")

    def tearDown(self) -> None:
        if self._old is None:
            os.environ.pop("ACS_GUARDIAN_HOST_ALLOWLIST", None)
        else:
            os.environ["ACS_GUARDIAN_HOST_ALLOWLIST"] = self._old

    def test_allowlist_unset_accepts_any_http(self) -> None:
        os.environ.pop("ACS_GUARDIAN_HOST_ALLOWLIST", None)
        acs_common.validate_guardian_url("http://127.0.0.1:8787/acs")
        acs_common.validate_guardian_url("http://anything.example.com/acs")

    def test_allowlist_restricts_to_listed_hosts(self) -> None:
        os.environ["ACS_GUARDIAN_HOST_ALLOWLIST"] = "127.0.0.1,guardian.internal"
        acs_common.validate_guardian_url("http://127.0.0.1:8787/acs")
        acs_common.validate_guardian_url("https://guardian.internal/acs")
        with self.assertRaises(ValueError):
            acs_common.validate_guardian_url("http://attacker.example.com/acs")


# ===== #10: Cursor session-state file collision across workspaces =====

class Item10_CursorStateCollision(unittest.TestCase):
    """Two different Cursor windows that happen to use the same
    session_id (non-UUID conversation IDs collide easily) MUST NOT share
    a session-state file. State file key must include cwd or workspace
    path so parent_step_id can't leak across workspaces."""

    def test_same_session_id_different_workspace_distinct_paths(self) -> None:
        # Two distinct workspaces, same session_id
        p1 = acs_common._session_state_path("conv-default", workspace="/a/work1")
        p2 = acs_common._session_state_path("conv-default", workspace="/b/work2")
        self.assertNotEqual(p1, p2,
            f"FIX REQUIRED: session-state path collides across workspaces: {p1}")


# ===== #11: Guardian schema-validates incoming envelopes =====

class Item11_GuardianValidatesIncoming(unittest.TestCase):
    """The Guardian MUST reject envelopes that don't match request-envelope.json
    before evaluating policy. Malformed envelopes that slip through can
    crash or mis-route the policy code."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _free_port()
        env = os.environ.copy()
        env["ACS_DEV_MODE"] = "1"
        env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.statedir = tempfile.mkdtemp(prefix="acs-guardian-state-")
        env["ACS_GUARDIAN_STATE_DIR"] = cls.statedir
        cls.proc = subprocess.Popen(
            [sys.executable, str(GUARDIAN), "--port", str(cls.port)], env=env,
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
        )
        _wait("127.0.0.1", cls.port)
        cls.url = f"http://127.0.0.1:{cls.port}/acs"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proc.terminate()
        try: cls.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired: cls.proc.kill()
        import shutil
        shutil.rmtree(cls.statedir, ignore_errors=True)

    def test_malformed_envelope_rejected_with_invalid_request(self) -> None:
        # Missing required `params` entirely
        body = json.dumps({"jsonrpc": "2.0", "id": "x", "method": "steps/sessionStart"}).encode()
        req = urllib.request.Request(self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode())
        self.assertIn("error", data,
            f"Guardian must reject schema-violating envelopes; got {data}")
        self.assertIn(data["error"]["code"], (-32600, -32602),
            f"expected -32600 Invalid Request / -32602 Invalid params; got {data['error']}")


# ===== #12: state-file hash length 16 → 64 =====

class Item12_StatePathHashLength(unittest.TestCase):
    """16 hex chars = 64-bit hash space. After billions of sessions,
    birthday collisions become possible. Use full SHA-256 (64 chars)."""

    def test_state_path_uses_full_sha256(self) -> None:
        p = acs_common._session_state_path("any-session-id")
        # Path stem (filename without extension) must be 64 hex chars
        self.assertRegex(p.stem, r"^[0-9a-f]{64}$",
            f"session-state filename {p.name!r} uses short hash; "
            f"expected 64-char SHA-256 hex digest")


# ===== #3: HA Guardian — file-locked merge =====

class Item03_HaGuardianFileLock(unittest.TestCase):
    """Two Guardian processes sharing a STATE_DIR must not lose
    replay-protection state. Process A accepts request X and persists;
    Process B must, on its next check_replay for the same session,
    re-read disk and see X."""

    def _start(self, port: int, statedir: str) -> subprocess.Popen:
        env = os.environ.copy()
        env["ACS_DEV_MODE"] = "1"
        env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env["ACS_GUARDIAN_STATE_DIR"] = statedir
        p = subprocess.Popen(
            [sys.executable, str(GUARDIAN), "--port", str(port)], env=env,
            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
        )
        _wait("127.0.0.1", port)
        return p

    def _post(self, port: int, body: dict) -> dict:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/acs",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return json.loads(resp.read().decode())

    def _envelope(self, sid, rid):
        return {"jsonrpc": "2.0", "id": str(uuid.uuid4()),
                "method": "steps/sessionStart",
                "params": {
                    "acs_version": "0.1.0", "request_id": rid,
                    "timestamp": acs_common.iso8601_now(),
                    "metadata": {"agent_id": "ha", "session_id": sid, "platform": "t"},
                    "payload": {},
                }}

    def test_second_guardian_sees_first_guardians_replay_state(self) -> None:
        with tempfile.TemporaryDirectory() as statedir:
            port_a, port_b = _free_port(), _free_port()
            proc_a = self._start(port_a, statedir)
            proc_b = self._start(port_b, statedir)
            try:
                sid = str(uuid.uuid4())
                rid = str(uuid.uuid4())
                # Guardian A accepts the request
                r_a = self._post(port_a, self._envelope(sid, rid))
                self.assertIn("result", r_a,
                    f"Guardian A must accept first send; got {r_a}")
                # Guardian B MUST reject the replay (shared state dir + file
                # locking + re-read on check_replay).
                r_b = self._post(port_b, self._envelope(sid, rid))
                self.assertIn("error", r_b,
                    "Guardian B accepted a replay of an envelope already "
                    "seen by Guardian A — HA file-locking + re-read on "
                    "check_replay broken; cross-instance replay window open")
                self.assertEqual(r_b["error"]["code"], -32005)
            finally:
                for p in (proc_a, proc_b):
                    p.terminate()
                    try: p.wait(timeout=2.0)
                    except subprocess.TimeoutExpired: p.kill()


if __name__ == "__main__":
    unittest.main(verbosity=2)
