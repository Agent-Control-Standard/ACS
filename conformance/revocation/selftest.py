#!/usr/bin/env python3
"""Negative controls for the runner and the adapter.

A conformance suite that has only ever been run against an implementation that
passes it has not been shown to discriminate. Everything here is a case the suite
MUST refuse, plus one case it must accept, so that a green result means the gate
is live rather than absent. Run it in CI beside the suite itself.

The adapter mutants matter as much as the fake adapters: each one deletes a single
check from the reference adapter, and the suite has to notice. A mutant that
survives is a vector nobody wrote.

    python conformance/revocation/selftest.py
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
RUNNER = HERE / "runner.py"
ADAPTER = HERE / "revocation_adapter.py"
VECTORS = HERE / "vectors" / "revocation_vectors.json"

FAKE_ADAPTERS = {
    "answer_key": (
        "# Enforces nothing: it would echo the expected verdict back. The runner never\n"
        "# hands it one, so it has nothing to echo.\n"
        "CAPABILITIES = ['revocation']\n"
        "def evaluate(v):\n"
        "    e = v['expected']\n"
        "    return {'verdict': e['verdict'], 'code': e.get('code'),\n"
        "            'reason': ' '.join(e.get('reason_must_mention', [])),\n"
        "            'entry_point': 'acme.enforce'}\n"
    ),
    "reject_everything": (
        "CAPABILITIES = ['revocation']\n"
        "def evaluate(v):\n"
        "    return {'verdict': 'REJECT', 'code': 'MANDATE_REVOKED',\n"
        "            'reason': 'revoked', 'entry_point': 'acme.enforce'}\n"
    ),
    "no_entry_point": (
        "CAPABILITIES = ['revocation']\n"
        "import sys; sys.path.insert(0, r'%s')\n" % HERE.resolve()
        + "from revocation_adapter import evaluate as _inner\n"
        "def evaluate(v):\n"
        "    out = dict(_inner(v)); out.pop('entry_point', None); return out\n"
    ),
    "empty_entry_point": (
        "CAPABILITIES = ['revocation']\n"
        "import sys; sys.path.insert(0, r'%s')\n" % HERE.resolve()
        + "from revocation_adapter import evaluate as _inner\n"
        "def evaluate(v):\n"
        "    out = dict(_inner(v)); out['entry_point'] = '   '; return out\n"
    ),
    "split_path": (
        "# Answers the must-pass inputs from a second path: a test double wired in\n"
        "# beside the enforcement layer, which is what the entry-point rule is for.\n"
        "CAPABILITIES = ['revocation']\n"
        "import sys; sys.path.insert(0, r'%s')\n" % HERE.resolve()
        + "from revocation_adapter import evaluate as _inner\n"
        "def evaluate(v):\n"
        "    out = dict(_inner(v))\n"
        "    if out['verdict'] == 'PASS':\n"
        "        out['entry_point'] = 'test_double.allow'\n"
        "    return out\n"
    ),
}

# Each mutant deletes one check from the reference adapter by rewriting a single
# line of its source. The suite must go red for every one of them.
ADAPTER_MUTANTS = {
    "drop_reachability_check": (
        r'if not registry\.get\("reachable"\):', 'if False:'),
    "drop_publication_interval_check": (
        r'if age > interval:', 'if False:'),
    "drop_supersession_check": (
        r'if auth\.get\("mandate_seq", 1\) > 1 and not auth\.get\("supersedes"\):', 'if False:'),
    "drop_revocation_lookup": (
        r'if mandate in revoked:', 'if False:'),
    "trust_party_asserted_time": (
        r'if revoked_at and not acted_at:', 'if False:'),
    "ignore_the_window_and_reject_on_the_list": (
        r'if acted_at and revoked_at and _instant\(acted_at\) <= _instant\(revoked_at\):',
        'if False:'),
    "blur_the_reason": (
        r'return reject\(f"mandate \{mandate\} is revoked"\)', 'return reject("revoked")'),
}


def run(adapter: Path, vectors: Path = VECTORS, profile: str | None = None):
    cmd = [sys.executable, str(RUNNER), "--adapter", str(adapter), "--vectors", str(vectors)]
    if profile is not None:
        cmd += ["--profile", profile]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def main() -> int:
    results = []

    def record(name, ok, detail):
        results.append((name, ok, detail))

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # The one case that must pass. Without it a green run proves only that
        # everything fails, which is the failure this whole file exists to catch.
        # The expected count is read from the suite rather than written here: a
        # hardcoded total silently stops matching the moment a vector is added.
        total = len(json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"])
        code, out = run(ADAPTER)
        record(
            "reference adapter conforms",
            code == 0 and f"{total}/{total} vectors conform" in out,
            f"exit {code}: {out}",
        )

        for name, source in FAKE_ADAPTERS.items():
            f = tmp / f"{name}.py"
            f.write_text(source, encoding="utf-8")
            code, out = run(f)
            record(f"refuses {name}", code != 0, f"exit {code}: {out}")

        original = ADAPTER.read_text(encoding="utf-8")
        for name, (pattern, replacement) in ADAPTER_MUTANTS.items():
            mutated, n = re.subn(pattern, replacement, original, count=1)
            if n != 1:
                record(f"mutant {name}", False, "the line this mutant targets is no longer there")
                continue
            f = tmp / f"mutant_{name}.py"
            f.write_text(mutated, encoding="utf-8")
            code, out = run(f)
            record(f"kills mutant {name}", code != 0, f"exit {code}: {out}")

        # A capability declared with nothing to certify it must fail loudly, which
        # is what stops --profile from being a way to opt out of being measured.
        code, out = run(ADAPTER, profile="revocation,quarantine")
        record("refuses a capability with no positive control", code == 2, f"exit {code}: {out}")

        # A vector file that does not match its pinned digest is not the suite.
        tampered = tmp / "vectors"
        tampered.mkdir()
        tampered_file = tampered / "revocation_vectors.json"
        tampered_file.write_text(
            VECTORS.read_text(encoding="utf-8").replace('"REJECT"', '"PASS"', 1), encoding="utf-8"
        )
        code, out = run(ADAPTER, vectors=tampered_file)
        record("refuses an unpinned vector file", code == 2, f"exit {code}: {out}")

    for name, ok, detail in results:
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            print(f"       {detail}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} negative controls held")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
