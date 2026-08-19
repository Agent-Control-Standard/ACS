"""
The drop-in settings.json.example — the file people copy — must itself
cover the Core-minimum hook set, with gate hooks fail-closed.

Emission proves the adapter CAN emit each hook when invoked; this puts
the checked-in EXAMPLE config under test, closing the "file people copy
isn't in the loop" gap that first shipped as Claude's 5-of-6 (PR #22
emission re-review).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
sys.path.insert(0, str(ADAPTER_DIR))
import wire  # noqa: E402


class ExampleConfigCoversCoreFloor(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = json.loads((ADAPTER_DIR / "settings.json.example").read_text())
        self.hooks = self.cfg.get("hooks", {})

    def test_example_wires_full_core_minimum(self) -> None:
        missing = set(wire.ACS_CORE_HOOKS) - set(self.hooks)
        self.assertEqual(missing, set(),
            f"settings.json.example (the copy-paste config) is missing "
            f"Core-minimum hooks {sorted(missing)}; wired: {sorted(self.hooks)}")

    def test_example_gate_hooks_are_fail_closed(self) -> None:
        """Gate hooks in the example must carry ACS_DEFAULT_DENY=1 — a
        silent fail-open on a gate is a policy hole."""
        for hook in wire.GATE_HOOKS & set(wire.ACS_CORE_HOOKS):
            entries = self.hooks.get(hook, [])
            self.assertTrue(entries, f"gate hook {hook} missing from example")
            env = entries[0]["hooks"][0].get("env", {})
            self.assertEqual(env.get("ACS_DEFAULT_DENY"), "1",
                f"gate hook {hook} in the example must set ACS_DEFAULT_DENY=1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
