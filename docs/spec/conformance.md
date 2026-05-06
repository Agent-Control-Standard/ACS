# Conformance Profiles

ACS v0.1.0 conformance is tiered. Every conformant deployment implements **ACS-Core** — the mandatory baseline below. Trace event emission, AgBOM serialization, field-level provenance, cryptographic signatures, and strengthened audit chains are organized as **profiles** that deployments declare independently in the [handshake](./instrument/specification.md#4-capability-negotiation-handshake).

The profile system lets a small harness ship a useful subset of ACS quickly, while a more capable deployment can layer on observability, supply-chain inventory, or cryptographic integrity without changing the wire format.

## Profile declaration

Profiles are declared in the handshake. ClientHello includes `profiles_supported: string[]`; ServerHello includes `profiles_accepted: string[]`. Profile names are the lowercase hyphenated forms below: `acs-core`, `acs-trace`, `acs-inspect`, `acs-inspect-dynamic`, `acs-provenance`, `acs-crypto`, `acs-audit`.

A Guardian MAY refuse a session if the client does not declare a profile the Guardian's policy requires (e.g. a Guardian whose policy needs provenance MAY refuse a client that does not declare `acs-provenance`).

## ACS-Core (mandatory baseline)

A v0.1.0-conformant deployment MUST implement ACS-Core. ACS-Core comprises:

- **Handshake** — `handshake/hello` with ClientHello/ServerHello ([Specification §4](./instrument/specification.md#4-capability-negotiation-handshake)).
- **Request/response envelope** — JSON-RPC 2.0 with ACS extensions ([§3](./instrument/specification.md#3-wire-format)). `request_id`, `timestamp`, `acs_version`, `metadata` required on every request.
- **Hook taxonomy** — At minimum: `sessionStart`, `userMessage` or `agentTrigger`, `toolCallRequest`, `toolCallResult`, `agentResponse`, `sessionEnd`. Additional hooks (`turnStart`/`turnEnd`, `preCompact`/`postCompact`, `subagentStart`/`subagentStop`, `knowledgeRetrieval`, `memoryContextRetrieval`, `memoryStore`) are normatively defined and SHOULD be implemented when the harness can observe the corresponding event; they are capability-negotiated via the handshake.
- **Dispositions** — All five (ALLOW, DENY, MODIFY, ASK, DEFER) with required fields per [§6](./instrument/specification.md#6-disposition-vocabulary).
- **SessionContext and Intent** — `session_id`, `chain_hash` (rolling SHA-256), append-only ContextEntry chain ([§8](./instrument/specification.md#8-sessioncontext-and-intent)). Intent is optional but normative when IBAC is the enforcement paradigm.
- **Replay protection** — `request_id` (UUID) and `timestamp` on every request; Guardians MUST reject replays per [§10.3](./instrument/specification.md#103-replay-protection).
- **Liveness** — `system/ping` ([§13](./instrument/specification.md#13-liveness--system-methods)).
- **Wrapped MCP** — `protocols/MCP/*` ([Hooks](./instrument/hooks.md#protocolsmcp)).

ACS-Core does NOT require: field-level Provenance objects, Trace event emission, AgBOM, cryptographic signatures, or `request_hash` on ContextEntry (`request_hash` remains SHOULD).

## ACS-Trace

Adds deterministic Trace event emission per [Trace Events](./trace/events.md). A deployment claiming ACS-Trace MUST:

1. Emit at least one of {OTel, OCSF} for every supported ACS step, with the required attributes populated.
2. Record decisions as Trace events.
3. Carry provenance facts forward onto Trace events.

Required for deployments that need cross-vendor observability or SIEM integration. Trace events MUST NOT block enforcement.

## ACS-Inspect

Adds AgBOM snapshot emission per [Inspect](./inspect/README.md). A deployment claiming ACS-Inspect MUST:

1. Emit `agbom/snapshot` once per session before content-bearing hooks fire.
2. Have the Guardian serialize the canonical AgBOM into at least one of {CycloneDX 1.6, SPDX 3.0, SWID} on request.

Required when Guardian policy depends on component inventory.

### ACS-Inspect-Dynamic (extends ACS-Inspect)

Adds `agbom/changed` emission on every mid-session component mutation, with audit-chain integration. Required for deployments where agents hot-swap models, tools, or MCP servers.

## ACS-Provenance

Adds field-level Provenance objects ([§7](./instrument/specification.md#7-provenance)) to data-bearing fields. A deployment claiming ACS-Provenance MUST populate `provenance_id`, `origin`, and (when applicable) `derived_from` on Provenance-bearing fields.

The wire-format `trust` enum is OPTIONAL in v0.1; the v0.1 expected practice is for Guardians to derive trust from `origin` + `source_id` against local policy without populating the field. Vendor Guardian implementations that elect to populate `trust` on the wire MUST enforce the monotonicity rule on `agent_generated` trust and SHOULD use the default channel-to-trust mapping ([§7.2](./instrument/specification.md#72-default-channel-to-trust-mapping)) so cross-deployment audits remain portable.

Required for FIDES, CaMeL, and AARM-style enforcement paradigms (which depend on the trust *concept* — whether materialized on the wire or derived in policy). Not required for pure IBAC.

## ACS-Crypto

Adds cryptographic signature support beyond the baseline's replay-protection fields. A deployment claiming ACS-Crypto MUST support at least `ML-DSA-65` (RECOMMENDED primary) and SHOULD support `SLH-DSA-128s` as an algorithmic-diversity backup. Hybrid composites (`ML-DSA-65+ECDSA-P256`, `ML-DSA-65+RSA-PSS-SHA256`) are OPTIONAL for transitional deployments.

Baseline deployments without ACS-Crypto MAY use `HMAC-SHA256` for integrity or rely on transport-level security; neither is required by ACS-Core.

## ACS-Audit

Strengthens the audit chain beyond ACS-Core's baseline. A deployment claiming ACS-Audit MUST populate `request_hash` (lowercase-hex SHA-256 of JCS-canonicalized request params) on every ContextEntry, ensuring the chain commits to request content, not just step metadata. ACS-Audit deployments SHOULD also populate `timestamp` and `provenance_summary` on every ContextEntry.

## Profile combinations

Profiles compose. A deployment that wants full observability and supply-chain inventory but not cryptographic signatures declares `["acs-core", "acs-trace", "acs-inspect", "acs-provenance"]`. A high-assurance deployment declares all of `["acs-core", "acs-trace", "acs-inspect", "acs-inspect-dynamic", "acs-provenance", "acs-crypto", "acs-audit"]`. A minimal IDE harness declares `["acs-core"]` only.

## Quick reference

| Profile | What it adds | When to claim |
|---|---|---|
| `acs-core` | Handshake, envelope, hook taxonomy, dispositions, SessionContext, Intent, replay protection, ping | Always (mandatory) |
| `acs-trace` | OTel + OCSF event emission per step | Cross-vendor observability or SIEM integration |
| `acs-inspect` | `agbom/snapshot` + canonical AgBOM serialization | Policy depends on component inventory |
| `acs-inspect-dynamic` | `agbom/changed` on mutation | Agent hot-swaps components mid-session |
| `acs-provenance` | Field-level Provenance objects | Enforcing FIDES, CaMeL, or AARM-style information-flow paradigms |
| `acs-crypto` | ML-DSA-65 / SLH-DSA-128s signatures | Cryptographic integrity beyond shared-secret HMAC |
| `acs-audit` | `request_hash` on every ContextEntry | Chain must commit to request content |
