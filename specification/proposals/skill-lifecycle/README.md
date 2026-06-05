# Skill lifecycle hooks: threat model and design rationale

> This is the design record for the skill lifecycle hooks, which landed in v0.1.0. The normative schemas are canonical under [`specification/v0.1.0/`](../../v0.1.0/); this page keeps the threat model, literature, and decisions that justify them.

ACS governs every reasoning-context boundary except one: the skill. Sixteen `steps/*` hooks fire on tool calls, knowledge, memory, and subagents, but no hook sees a skill register, load, or unload. A skill slips into the agent unvetted, and the spec never gets a look.

v0.1.0 adds three hooks (`skillRegister`, `skillLoad`, `skillUnload`) and a `skill` component type. They close a gap that is both documented in the literature and, as of May 2026, **unclosed by any of the 39 agent frameworks surveyed**.

## The threat

Per-action evaluation cannot see a payload that lives in composition.

**SkillTrojan** ([Feng et al., 2026](https://arxiv.org/abs/2604.06811)) encrypts a malicious payload, splits it across a skill's normal actions, and reassembles it only when a trigger phrase appears. Each action is benign on its own. `toolCallRequest` fires on every one and correctly returns ALLOW: `query` looks like a query, `export` looks like an export. The malice exists only across the actions, where no per-action hook can reach. The attack hits 97.2% success on GPT-5.2 while preserving 89.3% clean accuracy, and the authors released 3,000+ backdoored skills to prove it scales.

The threat is not theoretical. **[Agent Skills in the Wild](https://arxiv.org/abs/2601.10338) (Liu et al., 2026)** found 26.1% of real-world skills carry at least one vulnerability and 5.2% show patterns that strongly suggest malicious intent. The paper names the root cause: a **consent gap**. Once a user approves a skill, it runs with implicit trust and minimal vetting.

Two related papers sharpen the picture, in opposite directions. **[BADSKILL](https://arxiv.org/abs/2604.09378)** bundles a backdoor-fine-tuned model inside the skill; the malice lives in learned weights, which the authors note "source-code inspection provides limited visibility" into, so they recommend treating model-bearing skills as provenance-sensitive artifacts and verifying their integrity. **[SkillAttack](https://arxiv.org/abs/2604.04989)** is a different attacker entirely: it crafts user prompts against an honest but vulnerable skill, does not touch the artifact ("an attacker can craft arbitrary user prompts ... but cannot modify the skill itself"), and proposes no defense (the authors state skill-level safeguards "remain future work"). It marks the outer boundary of what these hooks address rather than motivating them, and the data model does not claim to catch it. Across the three artifact-borne attacks the defense converges on one point: vet the skill before it runs, by inspection where the artifact is readable and by integrity and provenance where it is not.

## Why existing hooks fall short

A Guardian that keeps session state can reconstruct the runtime *sequence* of tool calls from `session_id`, `turn_id`, and per-argument provenance. But by then each benign fragment has already run. The precise gap is narrower than "runtime blindness":

**No hook sees the whole skill definition before any of its actions execute.** And ACS does not model skills at all. The data model has `tool` and `agent_capability`, nothing for loadable executable content.

The cross-framework survey confirms this is industry-wide. Of 211 hooks across 39 frameworks, zero govern skills. Frameworks built component-supply-chain controls for MCP (trust flags, permission manifests, allow/reject rules) and left skills, a documented supply-chain vector, unguarded.

## The design

Three hooks, two control points, one new component type.

| Hook | Fires | Catches | OWASP |
|---|---|---|---|
| `skillRegister` | Skill enters the available set, before it can load | Compositional payloads (whole-definition inspection); over-broad manifests; unsigned or untrusted-origin skills; poisoned dependencies | ASI04, ASI02 |
| `skillLoad` | Registered skill activates into a session, before its actions run | Load-time activation; tampered artifacts; inter-skill cascades via the load path | ASI08, ASI06 |
| `skillUnload` | Skill leaves the active set | Load/unload churn as evasion; AgBOM inventory accuracy | ASI10 |

`skillRegister` and `skillLoad` are deliberately distinct. Registration vets the artifact once, statically. It is the natural home for whole-definition analysis, signature checks, and dependency inspection, all cacheable. Load governs each activation in live context and carries the **load path**, the ordered list of skills that led to the current load. That path is what lets a Guardian contain cascades: a skill loading another skill outside its declared `composed_skills` is denied.

The load path reuses the `subagentStart` parent-step vocabulary rather than inventing one. Composition-policy intent rides `policy_data` and `reason_codes`. No new wire element appears where an existing one carries the signal (Spec Review Principle 4).

## How the spec addresses each threat model

Each paper names a distinct evasion, and this work and its review surfaced two further boundaries. The test is whether a mechanism closes each, not whether the spec mentions it.

| Threat | How ACS addresses it |
|---|---|
| **SkillTrojan**: payload split across a skill's actions, reassembled only at runtime | `skillRegister` exposes the whole definition for compositional static analysis before any action runs; the trigger and fragment-writing code live in the action scripts, so the composed artifact is inspectable as a unit, not action by action. The paper notes the assembled payload itself only materializes at runtime and is hidden in functional outputs, so register-time analysis of the composition is the primary control; deployments wanting more can layer their own runtime correlation over the existing per-step audit chain. |
| **BADSKILL**: backdoor in a bundled model's weights, opaque to source reading | `definition.digest` commits to the complete artifact including model weights, and `registration_provenance` attests its origin. The control is integrity and provenance, not body inspection, which matches the authors' own recommendation to treat model-bearing skills as provenance-sensitive artifacts. |
| **Agent Skills in the Wild**: the consent gap, approve-once then implicit trust | `skillRegister` is a per-registration gate rather than a one-time install prompt; `declared_capabilities` is the least-privilege manifest a Guardian checks against the capabilities the composed tools actually expose. |
| **Inter-skill cascade** (A loads B loads C, each clean alone): a boundary this work surfaced, not expressly called out in these papers | `composed_skills` declares the skills a skill may load and `load_path` carries the chain, reusing the `subagentStart` parent-step vocabulary, so a Guardian denies any load that escapes the declared set. A skill loading another skill outside its declared `composed_skills` is itself a boundary crossing; this work makes that crossing explicit so a Guardian can govern it. |
| **Load without registration** (raised in review): emit `skillLoad` for an artifact never vetted | `skillLoad` must correlate to an approved `skillRegister` by `(skill_id, digest)`; an uncorrelated or digest-mismatched load is unverifiable and denied, so the register gate cannot be skipped. |
| **SkillAttack**: crafted prompts against an honest but vulnerable skill | Out of scope for the lifecycle hooks. The malice is in the prompt and the data flow, not the artifact, so the existing per-action hooks (`toolCallRequest`) and data-flow provenance govern it. Listed to mark the boundary, not because a skill hook catches it. |

## Data model: a `skill` component, not a new object graph

A skill is a higher-level ability composed of lower-level components, which is exactly what `agent_capability` already models. So why a new type?

A skill carries one thing `agent_capability` does not: a **definition artifact**, the executable content attackers poison. That is a real trust-boundary crossing, and it is lost otherwise (Spec Review Principle 3). A passive capability grouping has no body to inspect; a skill does.

So `skill` joins the existing discriminator as an eighth component type, reusing the composition shape (`tools`, `mcp_servers`, `a2a_peers`) and adding:

- `definition`: a reference and integrity digest over the **complete loadable artifact**, including any bundled model weights or adapters, not only text. **The body never persists on the wire.** It travels only in the transient `skillRegister` payload for inspection; the AgBOM keeps `ref` + `digest`. This is what covers a BADSKILL-style weight backdoor: the digest and provenance bind the binary artifact even where source reading cannot see the payload.
- `declared_capabilities`: the skill's least-privilege manifest, which a Guardian compares against what the composed tools actually expose.
- `composed_skills`: the set of skills this skill may load, the containment boundary for cascades.
- `models`: the model components a skill bundles. This is how a BADSKILL-style model-bearing skill becomes legible without a new flag. The principled question (Spec Review Principles 3 and 4) is not "add a boolean," because a self-asserted `model_bearing` field is both attacker-controlled and redundant with the body the Guardian already holds at registration. The signal that is genuinely lost otherwise is the bundled model itself: the AgBOM persists only the skill's `ref` and `digest`, so the model never appears in the inventory. Listing it as a first-class `model` component reuses an existing type and gives the model its own `registration_provenance`, which is exactly the provenance-sensitive handling the BADSKILL authors recommend. The whole-artifact digest binds the weights regardless; `models` makes them visible to inventory and to load-time policy. A bundled classifier that does not fit the `model` component's contract (no served endpoint, no language-model context window) is still covered by the digest and provenance over the whole skill; expressing partial or embedded models in the `model` type is left to a later revision rather than relaxing that contract now.

See [`agbom/component.json`](../../v0.1.0/agbom/component.json) for the `skill` component type and its `skill_fields`.

## Normative requirements

These are mechanism requirements within the Instrument pillar; they live here, not hoisted (Spec Review Principle 1). The canonical calibration is the schema and hook catalog under `specification/v0.1.0/`; this list restates it.

1. A skill definition artifact MUST carry an integrity digest over the complete loadable artifact (text plus any bundled model assets). The AgBOM MUST persist the definition's `ref` and `digest`; it MUST NOT be required to persist the body.
2. `skillRegister` SHOULD fire before a skill becomes eligible to load. A Guardian MAY deny registration; a denied skill MUST NOT become loadable.
3. When a load is triggered by another skill, `skillLoad.load_trigger` MUST be `skill_composition` and `load_path` MUST contain more than one element.
4. A Guardian SHOULD deny a `skillLoad` whose `load_path` shows a skill loading another skill outside its declared `composed_skills`.
5. A Guardian SHOULD deny a `skillLoad` with `digest_verified: false`. The loaded artifact differs from the one vetted at registration.
6. A Guardian SHOULD compare `declared_capabilities` against the union of capabilities exposed by the composed tools and MAY deny over-broad declarations.
7. A `skillLoad` MUST be correlatable to a prior approved `skillRegister` for the same `(skill_id, digest)`. A Guardian SHOULD deny a load it cannot tie to an approved registration, or whose digest differs from the approved one; such a load is unverifiable. This closes the bypass where a framework emits `skillLoad` for an artifact that was never registered, or whose registration was denied.

## Scope boundary

Marketplace pre-publication scanning and publisher reputation are the marketplace's job. ACS surfaces the definition, provenance, and manifest at register and load so the Guardian's policy can act: pattern-match, static-analyze, verify a signature, or deny. The spec defines the control point; the deployment chooses what catches the attack.

The integrity digest binds the artifact as registered, not the code a skill fetches afterward. A skill that downloads and runs remote code at load or run time, the external-script-fetching and unpinned-dependency patterns documented in Agent Skills in the Wild, can carry code the digest never saw. That code does not escape governance: the fetch is a `network.egress` action and the execution a `process.execute` action, both intercepted by the existing per-action hooks, and `declared_capabilities` surfaces both at registration. The digest closes tampering of the registered bytes; it does not pin a skill's runtime-acquired dependencies, and the threat model does not claim it does.

The lifecycle hooks govern the artifact, not the prompt. An attack whose malice lives in a crafted user prompt against an honest but vulnerable skill (SkillAttack) is the existing per-action hooks' concern, governed where the action crosses the reasoning boundary and where data-flow provenance is checked, not at register or load. The skill hooks add a control point at the artifact boundary; they do not subsume the per-action layer.

## Where it lives in the spec

- `skill` component type: [`specification/v0.1.0/agbom/component.json`](../../v0.1.0/agbom/component.json)
- Hook payloads: [`skill-register.json`](../../v0.1.0/hooks/skill-register.json), [`skill-load.json`](../../v0.1.0/hooks/skill-load.json), [`skill-unload.json`](../../v0.1.0/hooks/skill-unload.json)
- Hook catalog and decision contracts: [`docs/spec/instrument/hooks.md`](../../../docs/spec/instrument/hooks.md#skillregister)
- Concept page: [`docs/concepts/skill.md`](../../../docs/concepts/skill.md)
- SBOM serialization: [`specification/v0.1.0/inspect/format-mapping.json`](../../v0.1.0/inspect/format-mapping.json)
