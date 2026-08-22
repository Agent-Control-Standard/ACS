"""Reference adapter: a minimal enforcement layer that satisfies the negative suite.

Ships WITH the suite for one reason: a runner nobody can execute end-to-end is a promise.
This adapter is the suite's own positive control. It is deliberately small and readable;
it is not a product.
"""


def evaluate(vector):
    inp = vector["input"]
    action, auth, state = inp.get("action", {}), inp.get("authorization", {}), inp.get("state", {})

    def reject(code, reason):
        return {"verdict": "REJECT", "code": code, "entry_point": "reference_adapter.decide", "reason": reason}

    def unmeasurable(code, reason):
        return {"verdict": "UNMEASURABLE", "code": code, "entry_point": "reference_adapter.decide", "reason": reason}

    # Evidence shape first: fail closed on what cannot be decoded, with its own code.
    oracle = state.get("oracle_response", "ABSENT_KEY")
    if oracle is None:
        return unmeasurable("ORACLE_UNAVAILABLE", "state could not be measured; absence is never a pass")
    if isinstance(oracle, dict):
        if oracle.get("shape") == "address" and not oracle.get("bytes_hex", "").startswith("0" * 24):
            return unmeasurable("MALFORMED_EVIDENCE", "leading bytes do not encode the declared address type")
        if oracle.get("shape", "").endswith("_6_fields") and oracle.get("fields_served") != 6:
            return unmeasurable("MALFORMED_EVIDENCE", f"expected 6 fields, served {oracle.get('fields_served')}")

    # Observability references: the omission itself is refused, before anything else.
    if "registry_ref" in action:
        ref = action["registry_ref"]
        if set(ref.replace("0x", "")) == {"0"}:
            return reject("REFERENCE_MISSING", "required registry reference is zeroed")
        target = state.get(action.get("target"), {})
        bound = target.get("bound_registry_ref")
        if bound and bound != ref:
            return reject("REFERENCE_MISMATCH", f"reference diverges from the one bound to this context ({bound})")

    # Principal binding.
    if auth.get("decision_for") and auth["decision_for"] != action.get("actor"):
        return reject("PRINCIPAL_MISMATCH", f"decision names agent {auth['decision_for']}, actor differs")
    if "required_signer" in action and auth.get("connected_device_derives") not in (None, action["required_signer"]):
        return reject("PRINCIPAL_MISMATCH", "connected device derives a different key; wrong device")

    # Replay.
    if auth.get("consumed"):
        return reject("REPLAY_CONSUMED", "this one-time authorization was already used")
    if auth.get("session_secret") and auth.get("current_session"):
        if auth["session_secret"] != f"SECRET_OF_SESSION_{auth['current_session']}":
            return reject("REPLAY_CONSUMED", "secret belongs to a previous session")

    # Freshness.
    if "decision_written_at" in auth:
        from datetime import datetime
        age = (datetime.fromisoformat(state["now"].replace("Z", "+00:00"))
               - datetime.fromisoformat(auth["decision_written_at"].replace("Z", "+00:00"))).total_seconds()
        if age > auth["freshness_bound_seconds"]:
            return reject("STALE_DECISION", f"decision is {int(age)}s old, freshness bound exceeded")

    # Context: signature validity alone never suffices; the state must carry the action.
    target = state.get(action.get("target"), {})
    if target.get("settled"):
        return reject("CONTEXT_NOT_SUPPORTED", "target auction is settled; this action replays a closed context")
    if "ceiling" in target and int(action.get("amount", 0)) > int(target["ceiling"]):
        return reject("CONTEXT_NOT_SUPPORTED", f"amount exceeds the ceiling the state carries ({target['ceiling']})")

    return {"verdict": "PASS", "code": None, "entry_point": "reference_adapter.decide", "reason": "context supports the action"}
