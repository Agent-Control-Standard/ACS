#!/usr/bin/env python3
"""Negative conformance runner (issue #29, gap #19).

Loads the vector suite, calls one implementation adapter per vector, and fails on:
  - any verdict mismatch,
  - any failure-code mismatch,
  - any missing reason substring (a right verdict for a wrong reason is a latent bug),
  - any category lacking its POSITIVE CONTROL.

The last rule is structural, not cosmetic: a suite made only of must-reject inputs cannot
distinguish an enforcement layer that works from one that rejects everything.

Adapter contract: a Python file exposing
    evaluate(vector: dict) -> {"verdict": "PASS|REJECT|UNMEASURABLE", "code": str|None, "reason": str}

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
    spec = importlib.util.spec_from_file_location("acs_adapter", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "evaluate"):
        sys.exit(f"FATAL: adapter {path} exposes no evaluate(vector)")
    return mod


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True, type=Path)
    ap.add_argument("--vectors", type=Path, default=HERE / "vectors" / "negative_vectors.json")
    args = ap.parse_args()

    suite = json.loads(args.vectors.read_text(encoding="utf-8"))
    vectors = suite["vectors"]
    adapter = load_adapter(args.adapter)

    # Structural gate first: every category present must carry a positive control.
    cats = defaultdict(lambda: {"neg": 0, "pos": 0})
    for v in vectors:
        cats[v["category"]]["pos" if v.get("positive_control") else "neg"] += 1
    missing = [c for c, k in sorted(cats.items()) if k["pos"] == 0]
    if missing:
        print(f"SUITE INVALID: categories without a positive control: {missing}")
        print("A suite of pure rejections cannot tell a working layer from one that rejects everything.")
        return 2

    failures = []
    for v in vectors:
        try:
            out = adapter.evaluate(v) or {}
        except Exception as e:  # an adapter crash is a failure, never a skip
            failures.append((v["id"], f"adapter raised {type(e).__name__}: {e}"))
            continue
        exp = v["expected"]
        if out.get("verdict") != exp["verdict"]:
            failures.append((v["id"], f"verdict {out.get('verdict')!r} != expected {exp['verdict']!r}"))
            continue
        if exp["verdict"] != "PASS":
            if out.get("code") != exp.get("code"):
                failures.append((v["id"], f"code {out.get('code')!r} != expected {exp.get('code')!r}"))
                continue
            reason = (out.get("reason") or "").lower()
            for needle in exp.get("reason_must_mention", []):
                if needle.lower() not in reason:
                    failures.append((v["id"], f"reason does not mention {needle!r}: {reason[:120]!r}"))
                    break

    print(f"{len(vectors) - len(failures)}/{len(vectors)} vectors conform "
          f"({sum(k['pos'] for k in cats.values())} positive controls across {len(cats)} categories)")
    for vid, why in failures:
        print(f"  FAIL {vid}: {why}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
