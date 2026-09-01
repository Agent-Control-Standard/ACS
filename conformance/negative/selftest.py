#!/usr/bin/env python3
"""Negative controls for the runner and the reference adapter.

A suite that has only ever been run against an implementation which passes it has
not been shown to discriminate. A verifier that rejected every input would pass every
must-reject vector ever written, and nothing here would notice. So every case below is
one the suite MUST refuse, paired with the one case it must accept, and a green result
means the gate is live rather than absent.

Three families, and the third is the one that finds vectors nobody wrote:

  FAKE ADAPTERS      implementations that enforce nothing, or that satisfy the letter of
                     the adapter contract while defeating its purpose.
  RUNNER GUARDS      inputs the runner itself must refuse before any adapter is consulted:
                     an empty suite, and a category with no positive control.
  ADAPTER MUTANTS    each deletes exactly one check from the reference adapter. The suite
                     has to go red for every one of them. A surviving mutant is not a
                     tolerable gap - it is a vector nobody wrote, and it names which one.

Every case declares the outcome it requires, so a case that starts passing for the wrong
reason shows up as a changed count rather than as silence.

    python conformance/negative/selftest.py
"""
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
RUNNER = HERE / "runner.py"
ADAPTER = HERE / "reference_adapter.py"
VECTORS = HERE / "vectors" / "negative_vectors.json"

_IMPORT_REAL = (
    "import sys; sys.path.insert(0, r'%s')\n" % HERE.resolve()
    + "from reference_adapter import evaluate as _inner\n"
)

# Adapters the suite must refuse. Each one is a way of being green while enforcing
# nothing, or of satisfying the entry-point contract without dispatching through the
# thing it names.
FAKE_ADAPTERS = {
    "answer_key": (
        "# Would echo the expected verdict back. The runner never hands it one, so it\n"
        "# has nothing to echo and fails on its first call.\n"
        "def evaluate(q):\n"
        "    e = q['expected']\n"
        "    return {'verdict': e['verdict'], 'code': e.get('code'),\n"
        "            'reason': ' '.join(e.get('reason_must_mention', [])),\n"
        "            'entry_point': 'acme.enforcement.decide'}\n"
    ),
    "reject_everything": (
        "# The case the positive controls exist for: refusing everything is not enforcing.\n"
        "def evaluate(q):\n"
        "    return {'verdict': 'REJECT', 'code': 'CONTEXT_NOT_SUPPORTED',\n"
        "            'reason': 'context does not carry this action',\n"
        "            'entry_point': 'acme.enforcement.decide'}\n"
    ),
    "allow_everything": (
        "def evaluate(q):\n"
        "    return {'verdict': 'PASS', 'code': None, 'reason': 'ok',\n"
        "            'entry_point': 'acme.enforcement.decide'}\n"
    ),
    "no_entry_point": (
        _IMPORT_REAL
        + "def evaluate(q):\n"
        "    out = dict(_inner(q)); out.pop('entry_point', None); return out\n"
    ),
    "blank_entry_point": (
        "# A name made of spaces is not a name. `if not ep` accepts it; a stripped test does not.\n"
        + _IMPORT_REAL
        + "def evaluate(q):\n"
        "    out = dict(_inner(q)); out['entry_point'] = '   '; return out\n"
    ),
    "split_path": (
        "# Answers the must-pass inputs from a second path: a test double wired in beside\n"
        "# the enforcement layer, which is what the entry-point comparison is for.\n"
        + _IMPORT_REAL
        + "def evaluate(q):\n"
        "    out = dict(_inner(q))\n"
        "    if out['verdict'] == 'PASS':\n"
        "        out['entry_point'] = 'test_double.allow'\n"
        "    return out\n"
    ),
    "right_verdict_wrong_reason": (
        "# A right verdict for a wrong reason is a latent bug, and reason_must_mention exists\n"
        "# to catch exactly this.\n"
        + _IMPORT_REAL
        + "def evaluate(q):\n"
        "    out = dict(_inner(q)); out['reason'] = 'refused'; return out\n"
    ),
    "right_verdict_wrong_code": (
        _IMPORT_REAL
        + "def evaluate(q):\n"
        "    out = dict(_inner(q))\n"
        "    if out.get('code'):\n"
        "        out['code'] = 'CONTEXT_NOT_SUPPORTED'\n"
        "    return out\n"
    ),
}

# Suites the runner must refuse before consulting any adapter.
def _suite_without_positive_control(vectors):
    """Every category keeps its must-reject vectors; the positive controls go."""
    return [v for v in vectors if v["expected"]["verdict"] != "PASS"]


RUNNER_GUARDS = {
    "empty_suite": (lambda vs: []),
    "no_positive_control": _suite_without_positive_control,
}

# Each mutant deletes ONE check from the reference adapter by rewriting a single line
# of its source. The suite must go red for every one. The pattern is matched against
# the file as shipped: a mutant that no longer applies is reported as such rather than
# counted as killed, because a rule that silently stops being tested is worse than one
# that fails.
ADAPTER_MUTANTS = {
    "drop_unreadable_state": (
        r'if oracle is None:', 'if False:'),
    "drop_address_shape_check": (
        r'if oracle\.get\("shape"\) == "address" and not oracle\.get\("bytes_hex", ""\)\.startswith\("0" \* 24\):',
        'if False:'),
    "drop_field_count_check": (
        r'if oracle\.get\("shape", ""\)\.endswith\("_6_fields"\) and oracle\.get\("fields_served"\) != 6:',
        'if False:'),
    "drop_zeroed_reference_check": (
        r'if set\(ref\.replace\("0x", ""\)\) == \{"0"\}:', 'if False:'),
    "drop_reference_binding_check": (
        r'if bound and bound != ref:', 'if False:'),
    "drop_principal_binding_check": (
        r'if auth\.get\("decision_for"\) and auth\["decision_for"\] != action\.get\("actor"\):',
        'if False:'),
    "trust_an_unmeasured_device": (
        r'if derived is None:', 'if False:'),
    "drop_wrong_device_check": (
        r'if derived != action\["required_signer"\]:', 'if False:'),
    "drop_replay_check": (
        r'if auth\.get\("consumed"\):', 'if False:'),
    "drop_session_binding_check": (
        r'if auth\["session_secret"\] != f"SECRET_OF_SESSION_\{auth\[.current_session.\]\}":',
        'if False:'),
    "drop_freshness_check": (
        r'if age > auth\["freshness_bound_seconds"\]:', 'if False:'),
    "drop_settled_context_check": (
        r'if target\.get\("settled"\):', 'if False:'),
    "drop_ceiling_check": (
        r'if "ceiling" in target and int\(action\.get\("amount", 0\)\) > int\(target\["ceiling"\]\):',
        'if False:'),
}


def run(adapter: Path, vectors: Path = VECTORS):
    cmd = [sys.executable, str(RUNNER), "--adapter", str(adapter), "--vectors", str(vectors)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def main() -> int:
    suite = json.loads(VECTORS.read_text(encoding="utf-8"))
    source = ADAPTER.read_text(encoding="utf-8")
    held, failed = 0, []

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # The acceptant. Without it, everything below could be green because the suite
        # refuses its input unconditionally, and no count here would say so.
        code, out = run(ADAPTER)
        if code == 0:
            held += 1
            print("  held  reference adapter is accepted (the pair for every refusal below)")
        else:
            failed.append(("reference_adapter", "the shipped adapter must pass, got exit "
                           f"{code}: {out.splitlines()[0] if out else ''}"))

        for name, body in FAKE_ADAPTERS.items():
            path = tmp / f"fake_{name}.py"
            path.write_text(body, encoding="utf-8")
            code, out = run(path)
            if code != 0:
                held += 1
                print(f"  held  fake adapter refused: {name}")
            else:
                failed.append((f"fake:{name}", "accepted an implementation that must be refused"))

        for name, build in RUNNER_GUARDS.items():
            path = tmp / f"vectors_{name}.json"
            path.write_text(json.dumps({**suite, "vectors": build(suite["vectors"])}),
                            encoding="utf-8")
            code, out = run(ADAPTER, path)
            if code != 0:
                held += 1
                print(f"  held  runner refused the suite: {name}")
            else:
                failed.append((f"guard:{name}", "ran a suite that cannot discriminate, and exited 0"))

        for name, (pattern, replacement) in ADAPTER_MUTANTS.items():
            mutated, n = re.subn(pattern, replacement, source, count=1)
            if n != 1:
                failed.append((f"mutant:{name}",
                               "pattern no longer matches the adapter - the rule it deletes is "
                               "not being tested any more, update or remove this mutant"))
                continue
            path = tmp / f"mutant_{name}.py"
            path.write_text(mutated, encoding="utf-8")
            code, out = run(path)
            if code != 0:
                held += 1
                print(f"  held  mutant killed: {name}")
            else:
                failed.append((f"mutant:{name}",
                               "survived - no vector exercises the check it deletes"))

    total = held + len(failed)
    print(f"\n{held}/{total} negative controls held")
    for name, why in failed:
        print(f"  FAIL {name}: {why}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
