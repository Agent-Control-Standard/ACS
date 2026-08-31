#!/usr/bin/env python3
"""Negative conformance runner (issue #29, gap #19).

Loads the vector suite, calls one implementation adapter per vector, and fails on:
  - any verdict mismatch,
  - any failure-code mismatch (positive controls included),
  - any missing reason substring (a right verdict for a wrong reason is a latent bug),
  - any category lacking its POSITIVE CONTROL (a control counts only if it expects PASS),
  - any adapter answer that names no entry_point, and any category whose positive
    controls dispatched through a different entry point than its negative vectors
    (a suite that certifies a test double certifies nothing - review 4996153628).

The last rule is structural, not cosmetic: a suite made only of must-reject inputs cannot
distinguish an enforcement layer that works from one that rejects everything.

Adapter contract: a Python file exposing
    evaluate(question: dict) -> {"verdict": "PASS|REJECT|UNMEASURABLE", "code": str|None,
                                 "reason": str, "entry_point": str}
where question carries only {"id", "category", "input"} - the expected verdict and the
control flag never leave the runner, so an adapter that would derive its verdict from
the answer has nothing to derive it from (review 5444732337, run against 459ec820:
a six-line answer-key adapter scored 18/18 while enforcing nothing) - and entry_point
names the production entry point the adapter dispatched through.

Usage:
    python runner.py --adapter path/to/adapter.py [--vectors vectors/negative_vectors.json]
"""
import argparse
import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent


def load_adapter(path: Path):
    # An adapter spanning several files must be able to import its siblings (review 4996153628).
    sys.path.insert(0, str(path.resolve().parent))
    spec = importlib.util.spec_from_file_location("acs_adapter", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "evaluate"):
        sys.exit(f"FATAL: adapter {path} exposes no evaluate(vector)")
    return mod


def is_positive_control(v):
    """A positive control is DECLARED and EXPECTS PASS - decided once, in the one function
    both sites call (review 5444732337: the structural gate applied this rule while the
    entry-point bucketing read the declared flag alone, so a must-reject vector carrying
    the flag was refused a place in the count and still landed in the positive bucket).
    A declared flag is not a positive control; only an expected PASS is (review 4996153628)."""
    return bool(v.get("positive_control")) and v["expected"]["verdict"] == "PASS"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True, type=Path)
    ap.add_argument("--vectors", type=Path, default=HERE / "vectors" / "negative_vectors.json")
    args = ap.parse_args()

    suite = json.loads(args.vectors.read_text(encoding="utf-8"))
    vectors = suite["vectors"]
    adapter = load_adapter(args.adapter)

    # An empty suite discriminates nothing, and the count it prints is what hides that:
    # "0/0 vectors conform" with a zero exit reads exactly like a suite that passed.
    # The rule the gate below enforces per category has to hold for the suite itself.
    if not vectors:
        print("SUITE INVALID: no vectors. An empty suite cannot distinguish an enforcement "
              "layer from one that does nothing, and reports a clean run either way.")
        return 2

    # Structural gate first: every category present must carry a positive control.
    cats = defaultdict(lambda: {"neg": 0, "pos": 0})
    for v in vectors:
        cats[v["category"]]["pos" if is_positive_control(v) else "neg"] += 1
    missing = [c for c, k in sorted(cats.items()) if k["pos"] == 0]
    if missing:
        print(f"SUITE INVALID: categories without a positive control: {missing}")
        print("A suite of pure rejections cannot tell a working layer from one that rejects everything.")
        return 2

    failures = []
    entry_points = defaultdict(lambda: {"pos": set(), "neg": set()})
    for v in vectors:
        # The adapter is never handed the answer: expected verdict and control flag stay in
        # the runner, so the answer-key family stops being something to detect and becomes
        # something that cannot be expressed (review 5444732337).
        try:
            question = {"id": v["id"], "category": v["category"], "input": v["input"]}
            out = adapter.evaluate(question) or {}
        except Exception as e:  # an adapter crash - or a malformed vector - is a failure, never a skip
            failures.append((v.get("id", "?"), f"adapter raised {type(e).__name__}: {e}"))
            continue
        exp = v["expected"]
        # The suite certifies an enforcement layer, not a test double (review 4996153628):
        # every adapter answer must name the production entry point it dispatched through.
        ep = out.get("entry_point")
        if not ep:
            failures.append((v["id"], "adapter reported no entry_point - cannot tell the enforcement layer from a test double"))
            continue
        entry_points[v["category"]]["pos" if is_positive_control(v) else "neg"].add(ep)
        if out.get("verdict") != exp["verdict"]:
            failures.append((v["id"], f"verdict {out.get('verdict')!r} != expected {exp['verdict']!r}"))
            continue
        # code and reason are compared on PASS vectors too (review 4996153628: a positive
        # control's code field previously went uncompared; the always-true conditional that
        # wrapped this block is gone - review 5444732337 called it, cosmetic and right).
        if out.get("code") != exp.get("code"):
            failures.append((v["id"], f"code {out.get('code')!r} != expected {exp.get('code')!r}"))
            continue
        reason = (out.get("reason") or "").lower()
        for needle in exp.get("reason_must_mention", []):
            if needle.lower() not in reason:
                failures.append((v["id"], f"reason does not mention {needle!r}: {reason[:120]!r}"))
                break

    # Category failures are counted apart from vector failures: subtracting them from the
    # vector total printed "17/18 vectors conform" on a suite whose 18 vectors all conformed,
    # which is a wrong number reported by the very line that is supposed to make the run legible.
    category_failures = []
    for c, k in sorted(entry_points.items()):
        if k["pos"] and k["neg"] and k["pos"] != k["neg"]:
            category_failures.append((f"cat{c}", f"positive controls resolved through {sorted(k['pos'])} but negatives through {sorted(k['neg'])} - the gate certified a different code path than the one negatively tested"))

    print(f"{len(vectors) - len(failures)}/{len(vectors)} vectors conform "
          f"({sum(k['pos'] for k in cats.values())} positive controls across {len(cats)} categories)")
    for vid, why in failures:
        print(f"  FAIL {vid}: {why}")
    for cid, why in category_failures:
        print(f"  FAIL {cid}: {why}")
    return 1 if (failures or category_failures) else 0


if __name__ == "__main__":
    sys.exit(main())
