"""Reference adapter for the revocation vectors.

Ships with the vectors because a vector nobody can execute end-to-end is a promise. It
answers the revocation path and nothing else, and it declares that in CAPABILITIES so the
runner knows which vectors it is claiming to be measured on.

It reads the action, the authorization and the state, and never the expected verdict. The
runner does not hand it one.

Two failure codes are added, and neither collapses into one already enumerated:

  MANDATE_REVOKED         REJECT        the withdrawal was read and found
  REVOCATION_UNCHECKABLE  UNMEASURABLE  the withdrawal state could not be read

STALE_DECISION cannot carry either. A revoked mandate inside its freshness bound is not
old, and reporting it stale sends an operator to look at clocks. This is the suite's own
rule 1 applied to a second axis: measured-and-wrong and could-not-measure stay apart.
"""

from datetime import datetime

REVOKED = "MANDATE_REVOKED"
UNCHECKABLE = "REVOCATION_UNCHECKABLE"

# What this implementation claims to enforce. The runner runs the vectors requiring these
# and reports the rest as out of profile, so a capability this adapter does not have stays
# an unfilled gap rather than a red result, and a capability it does claim must carry a
# positive control or the suite refuses.
CAPABILITIES = ["revocation"]

# The entry point every answer below dispatched through. The runner compares it for
# equality and never parses it. Note what that can and cannot do: it detects an adapter
# answering the must-pass inputs from a different path than the must-reject ones, and it
# cannot detect one naming a path it never called.
ENTRY_POINT = "revocation_adapter.decide"


def _instant(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def evaluate_revocation(vector):
    """Return a verdict dict, or None when this vector says nothing about revocation."""
    inp = vector["input"]
    auth, state = inp.get("authorization", {}), inp.get("state", {})
    registry = state.get("revocation_registry")
    if registry is None:
        return None

    def reject(reason):
        return {
            "verdict": "REJECT",
            "code": REVOKED,
            "reason": reason,
            "entry_point": ENTRY_POINT,
        }

    def unmeasurable(reason):
        return {
            "verdict": "UNMEASURABLE",
            "code": UNCHECKABLE,
            "reason": reason,
            "entry_point": ENTRY_POINT,
        }

    # Reachability first: an unread registry is never a clean registry.
    if not registry.get("reachable"):
        return unmeasurable(
            "revocation state could not be read; absence of measurement is never a pass"
        )

    # A registry past its own declared publication interval has stopped answering.
    interval = registry.get("publication_interval_seconds")
    if interval is not None and "signed_at" in registry and "now" in state:
        age = (_instant(state["now"]) - _instant(registry["signed_at"])).total_seconds()
        if age > interval:
            return unmeasurable(
                f"revocation registry last signed {int(age)}s ago, beyond its declared "
                f"publication interval of {int(interval)}s; the answer could not be measured"
            )

    revoked = set(registry.get("revoked", []))
    mandate = auth.get("mandate_id")

    # A superseding mandate must name the predecessor it replaces, or its own revocation
    # state is unmeasurable: a replacement and a re-labelled original look identical.
    if auth.get("mandate_seq", 1) > 1 and not auth.get("supersedes"):
        return unmeasurable(
            "superseding mandate names no predecessor; a replacement and a re-presented "
            "revoked original could not be told apart"
        )

    if mandate in revoked:
        # The window comparison is made against an authority-signed instant, never against
        # one the presenting party controls. Back-dating alone would otherwise rehabilitate
        # every act the revoked mandate ever authorized.
        acted_at = auth.get("authority_signed_at")
        revoked_at = registry.get("revoked_at")
        if acted_at and revoked_at and _instant(acted_at) <= _instant(revoked_at):
            return None  # authority-signed instant places the act before the withdrawal
        if revoked_at and not acted_at:
            return unmeasurable(
                "revocation carries an instant and the action carries none the authority "
                "signed; the window could not be measured against a party-asserted time"
            )
        if revoked_at:
            return reject(
                f"mandate {mandate} was revoked at {revoked_at}; the authority-signed "
                f"instant for this action is {acted_at}, after the withdrawal"
            )
        return reject(f"mandate {mandate} is revoked")

    return None


def evaluate(vector):
    out = evaluate_revocation(vector)
    if out is not None:
        return out
    # code is carried explicitly on a pass. The runner compares code on every vector,
    # including the positive controls, against expected.get("code"), which is None when the
    # vector omits the field. An omitted key would answer that comparison by accident.
    return {
        "verdict": "PASS",
        "code": None,
        "reason": "no withdrawal recorded against this mandate",
        "entry_point": ENTRY_POINT,
    }
