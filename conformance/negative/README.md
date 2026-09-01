# Negative conformance vectors for the enforcement layer

Implements the proposal of issue #29 and the conformance-suite gap of issue #19.

The security value of an enforcement point is defined by its behaviour on inputs that are
*almost* right. This directory holds test vectors for those inputs: actions that are correctly
signed but unauthorized, replayed, stale, bound to the wrong principal, carried by malformed
evidence, or stripped of their observability references.

## Design rules

**1. Two rejection verdicts, never one.** A rejection because evidence was measured and found
wrong (`REJECT`) is a different verdict from a rejection because evidence could not be measured
at all (`UNMEASURABLE`). Both must refuse the action. Collapsing them either lets unmeasurable
inputs fail open, or sends operators hunting for frauds that never happened. Every vector
declares which of the two it expects.

**2. Every category carries a positive control.** Each category includes at least one
almost-identical input that MUST pass. A suite made only of must-reject inputs cannot
distinguish an enforcement layer that works from one that rejects everything. The runner fails
the whole suite if any category lacks its positive control.

**3. Vectors are framework-agnostic.** A vector describes an action, its authorization
evidence, and the state the enforcement point can consult. It never references a specific
implementation. Each implementation provides one adapter (see `runner.py`).

**4. Declared gaps are part of the suite.** Category 3 (expired or revoked mandates) is
covered here for expiry only. Revocation vectors are absent because the contributing
implementation has no revocation mechanism, by documented decision, and vectors for a path
never exercised in production would be design fiction. The gap is stated rather than filled.
Contributions from implementations that exercise revocation are the way to close it.

## Failure codes (proposed enumeration)

| Code | Verdict | Meaning |
|---|---|---|
| `CONTEXT_NOT_SUPPORTED` | REJECT | Signature valid, but the consulted state does not carry this action (wrong target, closed auction, exceeded bound) |
| `REPLAY_CONSUMED` | REJECT | The authorization was already used once; one authorization covers one act |
| `STALE_DECISION` | REJECT | The evidence is older than the declared freshness bound |
| `PRINCIPAL_MISMATCH` | REJECT | Approval bound to a different agent, tool, or signing device than the one acting |
| `REFERENCE_MISSING` | REJECT | A required observability reference is present and unusable: zeroed, or bound to a different context |
| `REFERENCE_MISMATCH` | REJECT | The named reference diverges from the one already bound to this action's context |
| `MALFORMED_EVIDENCE` | UNMEASURABLE | Evidence present but not decodable to the declared shape; consumers must fail closed |
| `ORACLE_UNAVAILABLE` | UNMEASURABLE | The state needed to judge could not be read; absence of measurement is never a pass |

## Vector schema

All eighteen vectors live as a single array in `vectors/negative_vectors.json`; the schema
below describes one entry.

```json
{
  "id": "neg-cat1-001",
  "category": 1,
  "description": "what makes this input almost right, and why it must fail",
  "input": {
    "action": { },
    "authorization": { },
    "state": { }
  },
  "expected": {
    "verdict": "REJECT | UNMEASURABLE | PASS",
    "code": "one of the enumeration above, absent for PASS",
    "reason_must_mention": ["substring the refusal message must contain"]
  },
  "positive_control": false
}
```

`reason_must_mention` exists because a correct verdict with a wrong reason is a latent bug:
an enforcement point can reject for the wrong cause and pass the suite while hunting the
wrong class of attack.

## Running

```
python conformance/negative/runner.py --adapter your_adapter.py
```

The adapter exposes `evaluate(question) -> {"verdict": ..., "code": ..., "reason": ...,
"entry_point": ...}`, where `question` carries only `{"id", "category", "input"}` - the
expected verdict and the `positive_control` flag never leave the runner - and `entry_point`
names the production entry point the adapter dispatched through for that vector. The runner
exits non-zero on: an empty suite, any verdict mismatch, any code mismatch (positive
controls included), any missing `reason_must_mention` substring, any category lacking a
positive control (a control counts only if it expects `PASS`), any answer naming no entry
point, or any category whose positive controls resolved through a different entry point
than its negative vectors. Vector failures and category failures are counted and reported
separately, so the conformance count never absorbs a category-level result.

The answer key is handled one layer earlier: since the adapter is never handed the expected
verdict, an adapter that would derive its answer from it has nothing to derive it from, and
fails on its first call. That family is no longer something the suite detects, it is
something that cannot be expressed (review of 2026-08-27, run against `459ec820`: a
six-line answer-key adapter scored 18/18 under the previous contract, and scores 0/18 with
`KeyError: 'expected'` under this one).

The entry-point rules remain a declaration the runner compares only against itself. They
catch a suite whose positive controls and negative vectors resolve through different paths;
they do not establish that the named function ran. Observing execution from outside the
adapter is the mechanism that would, and it is discussed in #35.

An empty vector file is refused. A suite with no vectors distinguishes nothing, and the
count it would otherwise print - `0/0 vectors conform` with a zero exit - is
indistinguishable from a suite that passed. The rule the structural gate applies per
category applies to the suite itself.

## Negative controls for the suite itself

```
python conformance/negative/selftest.py
```

A suite that has only ever been run against an implementation which passes it has not been
shown to discriminate, and a verifier that rejected every input would pass every must-reject
vector ever written. `selftest.py` is the pairing: twenty-four cases the suite must refuse,
plus the one it must accept, so that a green run means the gate is live rather than absent.

Three families. **Fake adapters** enforce nothing or satisfy the letter of the adapter
contract while defeating its purpose: one that would read the answer key, one that refuses
everything, one that allows everything, one that names no entry point, one whose entry point
is only whitespace, one that answers the must-pass inputs from a second path, and two that
return the right verdict with the wrong code or the wrong reason. **Runner guards** are
inputs refused before any adapter is consulted: an empty suite, and a suite whose positive
controls have been removed. **Adapter mutants** delete exactly one check from the reference
adapter, one mutant per check, and the suite has to go red for every one.

The mutants are the part that finds vectors nobody wrote. A mutant that survives is not a
tolerable gap: it names a rule the suite claims to enforce and does not exercise. Two came
out of the first run of this file. The entry-point check accepted a name made of spaces,
because `if not ep` is true for `""` and false for `"   "`. And the rule refusing an action
whose signing device was never read survived its own deletion, because no vector exercised
it - `neg-cat4-003` is that vector, and it was written because the mutant lived. A mutant
whose pattern no longer matches the adapter is reported as such rather than counted as
killed, so a rule that silently stops being tested shows up as a changed count.

## Provenance

Vectors are generalized from an enforcement layer running in production since June 2026
(hash-chained decision registries, out-of-band human confirmation, on-chain context checks).
Each rejection code in the enumeration was produced by a real refusal before it was named
here. The field notes behind them are public: https://github.com/avp9-nexus/nexus-art
