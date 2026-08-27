# Revocation conformance vectors

Nine vectors covering what an enforcement point must do when an authorization was
valid when it was written and has since been withdrawn. Six are refusals, three are
positive controls, and all nine are scoped to a declared `revocation` capability so
that an implementation without one reports an unfilled gap instead of a red result.

Everything here is self-contained: the vectors, the schema they validate against, a
reference adapter that answers them, the runner that scores them, a digest manifest
that pins them, and a set of negative controls that prove the scoring can fail.

```
python conformance/revocation/runner.py \
    --adapter conformance/revocation/revocation_adapter.py
python conformance/revocation/selftest.py
```

## Two failure codes

| Code | Verdict | Meaning |
|---|---|---|
| `MANDATE_REVOKED` | REJECT | The withdrawal was read and found. The authorization was valid when written and has since been withdrawn by its issuer. |
| `REVOCATION_UNCHECKABLE` | UNMEASURABLE | The withdrawal state could not be read, or could not be attributed to what is being presented. |

Neither collapses into a staleness code. A mandate revoked inside its freshness bound
is not old, and reporting it stale sends an operator to look at clocks. That is the
measured-and-wrong versus could-not-measure distinction applied to a second axis: old
and withdrawn are as different as wrong and unreadable.

## What the vectors cover

| Vector | What it is |
|---|---|
| `neg-cat3-002` | Withdrawn inside the freshness window. A freshness check alone passes this and the layer fails open. |
| `pos-cat3-002` | Control: registry reachable and clean. A layer that refuses whenever it consults a registry at all is indistinguishable from one that refuses everything. |
| `neg-cat3-003` | Registry unreachable. Absence of measurement is never a pass, and the code must differ from a measured withdrawal. |
| `neg-cat3-004` | Registry stale beyond its own declared publication interval. Reading a registry that stopped publishing as clean converts an outage into an allow. |
| `neg-cat3-005` | Back-dated window. The comparison is made against an authority-signed instant, never one the presenting party controls. |
| `neg-cat3-006` | Re-issued mandate naming no predecessor. A replacement and a revoked original under a new identifier cannot be told apart. |
| `pos-cat3-003` | Control: the same re-issue, naming the predecessor. The check is on an unresolvable link, not on the act of replacing a revoked mandate. |
| `neg-cat3-007` | Revoked, with no authority-signed instant to compare against. Rejecting would be a guess and passing would accept a back-dated claim. |
| `pos-cat3-004` | Control: the authority-signed instant precedes the withdrawal. A withdrawal ends an authorization going forward and does not unwind what it already authorized. |

The last two exist because mutation testing demanded them. Each mutant in
`selftest.py` deletes one check from the reference adapter, and two of them survived
against the first seven vectors: an adapter that trusted a party-asserted time, and
one that rejected on the presence of an identifier in the revoked list without ever
measuring the window. Both survived because no vector exercised the branch. A
surviving mutant is a vector nobody wrote, so the two were written.

## Capability profiles

A vector declares what it needs:

```json
"requires": ["revocation"]
```

An implementation declares what it has, either in the adapter as `CAPABILITIES` or on
the command line as `--profile`. The runner runs the vectors inside the profile and
reports the rest as out of profile. There is no third state: an adapter that declares
nothing and is given no profile is a fatal error rather than a silent run of
everything, because a profile inferred from the vectors would mean every
implementation claims every capability the suite happens to ship.

The flag is not a way to opt out of being measured. A capability inside the profile
that no positive control exercises fails the suite outright, which means declaring
`revocation` obliges you to pass the must-pass vectors and not only to refuse the
must-reject ones.

## The adapter contract

```python
CAPABILITIES = ["revocation"]

def evaluate(question) -> {"verdict": "PASS|REJECT|UNMEASURABLE",
                           "code": str | None,
                           "reason": str,
                           "entry_point": str}
```

The adapter is handed the vector's `id`, `category` and `input`. It is not handed
`expected` or `positive_control`. Those stay with the runner, so an adapter that
would derive its answer from the expected verdict has nothing to derive it from, and
that entire family of tautological adapters stops being detectable-in-principle and
starts being impossible. This is the cheapest structural property in the suite and it
subsumes every heuristic aimed at the same problem.

`entry_point` names the production path the answer came through. The runner compares
it for equality and never parses or interprets it, because an adapter names its own
entry points and a runner that recognises particular names holds an opinion about
adapter internals and stops working for the next implementer. The predicate is
sameness of path, not identity of path. Be precise about what that buys: it catches
an adapter answering the must-pass inputs from one path and the must-reject inputs
from another, and it cannot catch one that names a path it never called. An absent or
blank value is a refusal rather than a pass, because empty equals empty and the check
would otherwise hold vacuously in exactly the case it exists to fire on.

## Negative controls

`selftest.py` is the reason to believe any of the above. It runs fifteen cases: one
that must pass, five fake adapters that must be refused, seven single-line mutants of
the reference adapter that must be killed, a capability declared with no positive
control, and a vector file edited away from its pinned digest.

A suite only ever run against an implementation that passes it has not been shown to
discriminate, and a gate that has never been observed to fail is indistinguishable
from one that is not running.

## Pinning

`MANIFEST.json` carries a SHA-256 for every file here, and the runner refuses a vector
file whose digest does not match. A suite that can be edited between publication and
use proves nothing about the implementation that ran it. Regenerate the manifest
deliberately, in the same commit as the change it covers.
