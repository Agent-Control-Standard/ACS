"""
wire.py installer tests for the Cursor adapter.

Guards the DEFAULT install path — the one a user actually follows —
against silently dropping a Core-floor hook. subagentStart is the
confused-deputy spawn gate (Core floor post-#21); it was in the adapter
and in hooks.json.example but NOT in wire.py's default ACS_CORE_HOOKS,
so `wire.py --write` with no --hooks produced a config missing the gate
while the README claimed full coverage (PR #22 sixth review). These
tests run the real CLI and assert the generated hooks.json.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
WIRE = HERE.parent / "wire.py"


def _run_default_wire() -> dict:
    """Run wire.py with the DEFAULT hook set (no --hooks) and --write to
    a temp hooks.json; return the parsed result."""
    with tempfile.TemporaryDirectory() as d:
        settings = Path(d) / "hooks.json"
        secret = Path(d) / "hmac.key"
        secret.write_text("0" * 64)
        proc = subprocess.run(
            [sys.executable, str(WIRE),
             "--guardian-url=http://127.0.0.1:8787/acs",
             f"--secret-file={secret}",
             f"--settings={settings}",
             "--write"],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"wire.py --write failed ({proc.returncode}):\n{proc.stderr}")
        return json.loads(settings.read_text())


class DefaultWiringCoversCoreFloor(unittest.TestCase):
    def setUp(self) -> None:
        self.hooks = _run_default_wire().get("hooks", {})

    def test_subagent_start_is_fail_closed_both_mechanisms(self) -> None:
        """subagentStart is a gate: it must carry BOTH Cursor's native
        failClosed:true AND our ACS_DEFAULT_DENY=1 (defense in depth)."""
        entries = self.hooks.get("subagentStart", [])
        self.assertTrue(entries, "subagentStart has no entries")
        entry = entries[0]
        self.assertTrue(entry.get("failClosed") is True,
            f"subagentStart must set failClosed:true; got {entry}")
        self.assertIn("ACS_DEFAULT_DENY=1", entry.get("command", ""),
            f"subagentStart command must set ACS_DEFAULT_DENY=1; got "
            f"{entry.get('command')!r}")

    def test_default_covers_full_core_minimum_set(self) -> None:
        """Regression: the whole Core minimum set is wired, not a
        subset. Mirror wire.py's own ACS_CORE_HOOKS so the two can't
        drift silently."""
        sys.path.insert(0, str(WIRE.parent))
        import wire  # noqa: E402
        for hook in wire.ACS_CORE_HOOKS:
            self.assertIn(hook, self.hooks,
                f"default wiring missing Core hook {hook!r}; "
                f"wired: {sorted(self.hooks)}")


class ExampleConfigCoversCoreFloor(unittest.TestCase):
    """The drop-in `hooks.json.example` — the file people actually copy
    — must itself cover the Core-minimum hook set. Emission proves the
    adapter CAN emit each hook when invoked, and test_wire proves
    `wire.py --write`; neither reads the checked-in example. The example
    shipped missing afterAgentResponse + sessionEnd (same bug class as
    the original Claude 5-of-6; PR #22 emission re-review), so put the
    example itself under test."""

    def test_example_wires_full_core_minimum(self) -> None:
        import json
        example = json.loads((HERE.parent / "hooks.json.example").read_text())
        wired = set(example.get("hooks", {}))
        sys.path.insert(0, str(WIRE.parent))
        import wire  # noqa: E402
        missing = set(wire.ACS_CORE_HOOKS) - wired
        self.assertEqual(missing, set(),
            f"hooks.json.example (the copy-paste config) is missing "
            f"Core-minimum hooks {sorted(missing)}; wired: {sorted(wired)}")

    def test_example_gate_hooks_fail_closed_on_BOTH_mechanisms(self) -> None:
        """A gate hook in the drop-in example must carry BOTH:
        Cursor's native failClosed:true AND the adapter's
        ACS_DEFAULT_DENY=1 env var. failClosed alone only catches a
        crash / non-zero exit; the adapter exits 0 on a build failure
        (empty session_id, bad stdin) under the §6.4 fail-open default,
        so WITHOUT ACS_DEFAULT_DENY=1 a drop-in of the example is
        fail-OPEN on adapter build failure (PR #22 emission re-review —
        the earlier test only checked failClosed and stayed green while
        the example was fail-open, the same 5-of-6 class of gap)."""
        import json
        example = json.loads((HERE.parent / "hooks.json.example").read_text())
        sys.path.insert(0, str(WIRE.parent))
        import wire  # noqa: E402
        # Every hook the example marks failClosed is a gate; each MUST
        # also set ACS_DEFAULT_DENY=1. (Covers the Core-min gates AND the
        # shell/MCP gates.)
        checked = 0
        for hook, entries in example["hooks"].items():
            entry = entries[0]
            if entry.get("failClosed") is True:
                checked += 1
                self.assertIn("ACS_DEFAULT_DENY=1", entry.get("command", ""),
                    f"gate hook {hook} sets failClosed:true but NOT "
                    f"ACS_DEFAULT_DENY=1 — fail-open on adapter build failure")
        # And every Core-min gate hook must actually be a fail-closed gate.
        for hook in wire.GATE_HOOKS & set(wire.ACS_CORE_HOOKS):
            entry = example["hooks"].get(hook, [{}])[0]
            self.assertTrue(entry.get("failClosed") is True
                            and "ACS_DEFAULT_DENY=1" in entry.get("command", ""),
                f"Core-min gate hook {hook} must set BOTH failClosed:true "
                f"and ACS_DEFAULT_DENY=1")
        self.assertGreater(checked, 0, "no failClosed gate hooks found?")


if __name__ == "__main__":
    unittest.main(verbosity=2)
