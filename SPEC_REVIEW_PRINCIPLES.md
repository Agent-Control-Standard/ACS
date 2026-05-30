# ACS Spec Review Principles

These are the standing judgment calls behind ACS spec decisions. Load this into a coding agent's context when designing, reviewing, or critiquing changes to the schema, hooks, events, or written specification. It pairs with `STYLE.md`: STYLE governs how we write prose, this governs how we decide what goes in the spec.

Each principle is a heuristic, a smell test, and a worked example from a real v0.1.0 decision. Apply them; don't recite them.

## 1. Normative statements live at the altitude of their scope

A `MUST` belongs wherever its truth holds, not wherever it was first written.

- **Cross-cutting invariant** — true across pillars → define it once, above the pillars, tagged NORMATIVE. *e.g. "`Intent.parsed` MUST NOT be modified by the LLM or by data crossing an untrusted channel."* Intent flows through all three pillars (Instrument fires decisions against it, Trace records it, Inspect catalogs what it authorized), so the invariant lives above them.
- **Mechanism requirement** — true within one pillar's enforcement → keep it in that pillar. *e.g. "the Guardian MUST verify approver identity," "a client declaring `provenance_producer: none` MUST be refused at handshake."*

**Smell test:** if a requirement is restated in two pillars, or buried in one pillar but relied on by another, it's at the wrong altitude. Hoist the invariant; leave the mechanics.

## 2. Every wire decision balances six constituencies

A change that optimizes one constituency at the others' expense is suspect. Name the trade before deciding.

1. **Expressiveness** — can the spec describe the real governance situation at all?
2. **Framework implementers** — can they reach conformance cheaply? This guards the adoption floor.
3. **Vendors and competitors** — is there room to build differentiated solutions on top? Don't absorb the value vendors should compete on.
4. **Adopters and deployments** — is integration cost low?
5. **Wire minimalism** — expressive enough *without* premature functionality or contract bloat that ossifies around guesses.
6. **Security reality** — does it match where boundary crossing and trust-laundering actually occur?

**Smell test:** "more fields" or "more guidance" usually pays constituency 1 by taxing 2, 3, and 5. If you can't name who you're taxing, you haven't finished the analysis.

## 3. Put it on the wire only if it's lost otherwise

This operationalizes Principle 2. A field earns a place in the contract only if it does one of two things:

- **(a)** captures information lost or unreconstructable downstream, or
- **(b)** marks a real trust-boundary crossing.

Everything else belongs in `policy_data`, a conformance profile, or vendor territory.

- **On the wire:** provenance that must travel across summarization, memory writes, and agent hops. Drop it and trust launders silently and unrecoverably.
- **Not on the wire:** risk category, data classification, retention period, control mapping. These are reconstructable from policy plus logs; forcing them into the contract raises the floor (2.2) and commoditizes vendor value (2.3).

**Smell test:** "could a deployment reconstruct this after the fact from what it already logs?" If yes, keep it off the wire.

## 4. The wire is paradigm-neutral; new paradigms ride existing elements first

We name four control paradigms today — IBAC, FIDES, CaMeL, AARM — but these are points on a wider space. They represent different philosophical approaches to crafting effective controls, each grounded in existing standards and research. Others will need support over time, and the contract must accommodate them without being re-cut for each one.

The wire stays neutral. A new paradigm reaches the wire through the elements that already carry paradigm-specific intent:

- `reason_codes` — free vocabulary for machine-readable categorization.
- `policy_data` — free-form payload, conventionally keyed by paradigm name (`{"ibac": {...}, "fides": {...}}`).
- `policy_references` — one entry per paradigm when several reject the same action.
- conformance profiles — when a paradigm needs a declarable capability tier.

A new paradigm earns a wire `MUST` only when it needs a signal none of these can already carry. That is Principle 3 applied to paradigms: if the needed information is expressible through existing conformant elements, it is not a spec change — it is a deployment or profile.

**Smell test:** "does this paradigm need a new wire field, or can it ride `policy_data`, `reason_codes`, or a profile?" If the latter, leave the wire alone. Prefer grounding the paradigm in an existing standard over inventing new surface.

---

*This file is meant to grow. Add a numbered section when a recurring judgment call earns the status of a principle.*
