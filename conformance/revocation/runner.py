#!/usr/bin/env python3
"""Capability-scoped conformance runner for the revocation vectors.

Runs one implementation adapter against a vector suite and refuses on:

  - any verdict, failure-code or reason mismatch, positive controls included;
  - any category, inside the declared profile, that carries no positive control;
  - any capability declared in the profile that no positive control exercises;
  - any adapter answer naming no entry point, or naming an empty one;
  - any category whose positive controls resolved through a different entry
    point than its negative vectors.

Two properties are worth stating plainly, because a runner that overstates what
it checks is worse than one that checks less.

The adapter never sees the answer key. It is handed the vector's id, category
and input, and nothing else. `expected` and `positive_control` stay with the
runner. An adapter that derives its answer from the expected verdict therefore
cannot answer at all, which removes that whole family of tautological adapters
rather than trying to detect one.

The entry point is compared for equality and never parsed. An adapter names its
own entry points, so the moment a runner recognises particular names it holds an
opinion about adapter internals and stops working for the next implementer. The
predicate is sameness of path, not identity of path. What this catches is an
adapter answering the must-pass inputs from one path and the must-reject inputs
from another. What it cannot catch is an adapter naming a path it never called.

Usage:
    python runner.py --adapter path/to/adapter.py [--profile revocation]
                     [--vectors vectors/revocation_vectors.json]
"""
import argparse
import hashlib
import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
MANIFEST = HERE / "MANIFEST.json"

EXIT_OK = 0
EXIT_FAILURES = 1
EXIT_SUITE_INVALID = 2


def load_adapter(path: Path):
    # An adapter spanning several files must be able to import its siblings.
    sys.path.insert(0, str(path.resolve().parent))
    spec = importlib.util.spec_from_file_location("acs_revocation_adapter", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not hasattr(mod, "evaluate"):
        sys.exit(f"FATAL: adapter {path} exposes no evaluate(vector)")
    return mod


def verify_digest(path: Path) -> str | None:
    """Return a complaint when the file does not match its pinned digest.

    A vector suite that can be edited between publication and use proves nothing
    about the implementation that ran it. Absent manifest entries are a refusal,
    never a pass, for the same reason an unread revocation registry is.
    """
    if not MANIFEST.exists():
        return f"no manifest at {MANIFEST}; the suite is unpinned"
    entries = json.loads(MANIFEST.read_text(encoding="utf-8"))["files"]
    name = path.resolve().name
    pinned = entries.get(name)
    if pinned is None:
        return f"{name} is not pinned in {MANIFEST.name}"
    actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != pinned:
        return f"{name} digest {actual} does not match pinned {pinned}"
    return None


def is_positive_control(vector) -> bool:
    """A declared flag is not a positive control; only an expected PASS is.

    One definition, so that every site deciding which vectors are the controls
    decides alike. Counting them in one place and bucketing them in another is
    how a suite ends up certifying a category that holds no must-pass input.
    """
    return bool(vector.get("positive_control")) and vector["expected"]["verdict"] == "PASS"


def resolve_profile(args, adapter) -> list[str]:
    """The capabilities an implementation claims to have.

    Given explicitly, or read from the adapter. Never inferred from the vectors:
    inferring it would mean every implementation declares every capability the
    suite happens to ship, which is the opposite of what the flag is for.
    """
    if args.profile is not None:
        return [c.strip() for c in args.profile.split(",") if c.strip()]
    declared = getattr(adapter, "CAPABILITIES", None)
    if declared is None:
        sys.exit(
            "FATAL: adapter declares no CAPABILITIES and no --profile was given. "
            "An undeclared profile is not an empty one, and guessing it would run "
            "vectors against a capability the implementation never claimed."
        )
    return list(declared)


def ask(adapter, vector):
    """Hand the adapter the question without the answer."""
    question = {"id": vector["id"], "category": vector["category"], "input": vector["input"]}
    return adapter.evaluate(question) or {}


def check_vector(adapter, vector, entry_points):
    """Return a complaint string, or None when the vector conforms."""
    try:
        out = ask(adapter, vector)
    except Exception as e:  # an adapter crash is a failure, never a skip
        return f"adapter raised {type(e).__name__}: {e}"

    ep = out.get("entry_point")
    if not isinstance(ep, str) or not ep.strip():
        # Empty equals empty, so an absent value would satisfy the equality check
        # below while measuring no path at all.
        return "adapter reported no entry point; the equality check would hold vacuously"
    entry_points[vector["category"]]["pos" if is_positive_control(vector) else "neg"].add(ep)

    exp = vector["expected"]
    if out.get("verdict") != exp["verdict"]:
        return f"verdict {out.get('verdict')!r} != expected {exp['verdict']!r}"
    if out.get("code") != exp.get("code"):
        return f"code {out.get('code')!r} != expected {exp.get('code')!r}"
    reason = (out.get("reason") or "").lower()
    for needle in exp.get("reason_must_mention", []):
        if needle.lower() not in reason:
            return f"reason does not mention {needle!r}: {reason[:120]!r}"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", required=True, type=Path)
    ap.add_argument("--vectors", type=Path, default=HERE / "vectors" / "revocation_vectors.json")
    ap.add_argument(
        "--profile",
        help="comma-separated capabilities this implementation claims; "
        "defaults to the adapter's CAPABILITIES",
    )
    args = ap.parse_args()

    complaint = verify_digest(args.vectors)
    if complaint:
        print(f"SUITE INVALID: {complaint}")
        return EXIT_SUITE_INVALID

    vectors = json.loads(args.vectors.read_text(encoding="utf-8"))["vectors"]
    adapter = load_adapter(args.adapter)
    profile = set(resolve_profile(args, adapter))

    in_profile, out_of_profile = [], []
    for v in vectors:
        needed = set(v.get("requires", []))
        (in_profile if needed <= profile else out_of_profile).append(v)

    # A declared capability with no positive control fails loudly. A capability an
    # implementation does not claim is silent, which is the whole point of the flag:
    # a declared gap stops being prose and an undeclared one stops being an excuse.
    uncontrolled = sorted(
        c
        for c in profile
        if not any(c in set(v.get("requires", [])) for v in in_profile if is_positive_control(v))
    )
    if uncontrolled:
        print(f"SUITE INVALID: capabilities declared with no positive control: {uncontrolled}")
        print("A capability certified only by refusals cannot be told from one that refuses everything.")
        return EXIT_SUITE_INVALID

    cats = defaultdict(lambda: {"neg": 0, "pos": 0})
    for v in in_profile:
        cats[v["category"]]["pos" if is_positive_control(v) else "neg"] += 1
    missing = [c for c, k in sorted(cats.items()) if k["pos"] == 0]
    if missing:
        print(f"SUITE INVALID: categories without a positive control: {missing}")
        return EXIT_SUITE_INVALID

    failures = []
    entry_points = defaultdict(lambda: {"pos": set(), "neg": set()})
    for v in in_profile:
        complaint = check_vector(adapter, v, entry_points)
        if complaint:
            failures.append((v["id"], complaint))

    for c, k in sorted(entry_points.items()):
        if k["pos"] and k["neg"] and k["pos"] != k["neg"]:
            failures.append(
                (
                    f"cat{c}",
                    f"positive controls resolved through {sorted(k['pos'])} but negative "
                    f"vectors through {sorted(k['neg'])}; the gate certified a different "
                    f"code path than the one negatively tested",
                )
            )

    print(
        f"{len(in_profile) - len(failures)}/{len(in_profile)} vectors conform "
        f"({sum(k['pos'] for k in cats.values())} positive controls across "
        f"{len(cats)} categories, profile {sorted(profile)})"
    )
    for v in out_of_profile:
        print(f"  OUT OF PROFILE {v['id']}: requires {sorted(set(v.get('requires', [])) - profile)}")
    for vid, why in failures:
        print(f"  FAIL {vid}: {why}")
    return EXIT_FAILURES if failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
