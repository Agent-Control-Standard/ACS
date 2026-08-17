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
| `REFERENCE_MISSING` | REJECT | A required observability reference is absent or zeroed |
| `REFERENCE_MISMATCH` | REJECT | The named reference diverges from the one already bound to this action's context |
| `MALFORMED_EVIDENCE` | UNMEASURABLE | Evidence present but not decodable to the declared shape; consumers must fail closed |
| `ORACLE_UNAVAILABLE` | UNMEASURABLE | The state needed to judge could not be read; absence of measurement is never a pass |

## Vector schema

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

The adapter exposes `evaluate(vector) -> {"verdict": ..., "code": ..., "reason": ...}`.
The runner exits non-zero on: any verdict mismatch, any code mismatch, any missing
`reason_must_mention` substring, or any category lacking a positive control.

## Provenance

Vectors are generalized from an enforcement layer running in production since June 2026
(hash-chained decision registries, out-of-band human confirmation, on-chain context checks).
Each rejection code in the enumeration was produced by a real refusal before it was named
here. The field notes behind them are public: https://github.com/avp9-nexus/nexus-art
