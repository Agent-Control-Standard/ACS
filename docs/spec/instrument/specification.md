# ACS v0.1.0 — Instrument Specification

**Version:** `0.1.0`

The Instrument pillar covers real-time interception, evaluation, and enforcement of agent behavior. It defines the wire format, the capability-negotiation handshake, the hook taxonomy, the disposition vocabulary, the SessionContext and Intent model, replay protection, and signature semantics. Trace (event emission) and Inspect (AgBOM) are co-equal v0.1.0 pillars covered in their own pages.

A deployment that implements **ACS-Core** (this section's mandatory baseline) is v0.1.0-conformant. Additional capabilities — Trace event emission, AgBOM serialization, field-level provenance, cryptographic signatures, strengthened audit chains — are organized as **conformance profiles** (see [Conformance](../conformance.md)).

## 1. Design Principles

1. **Opinionated on contract, permissive on implementation.** The wire format and semantics are locked. Engines, crypto suites, OS, and transport are deployment-owned.
2. **The agent MUST NOT have knowledge of hooks.** Provenance fields, when emitted, MUST be populated outside the LLM's output path.
3. **Facts on the wire; classification in policy.** Provenance fields (`origin`, `source_id`, `derived_from`) are populated by deterministic framework code at channel boundaries, never by the LLM. v0.1 keeps trust *classification* off the mandatory wire surface: Guardians derive trust from `origin` + `source_id` against local policy. The wire format reserves an OPTIONAL `trust` enum for vendor implementations that elect to carry the classification in the envelope; when populated, the monotonicity rule applies (§7).
4. **Three pillars, tiered conformance.** Instrument, Trace, and Inspect are all defined in v0.1.0. None is deferred. ACS-Core is the mandatory baseline; Trace, Inspect, Provenance, Crypto, and Audit are normative profiles deployments advertise via handshake negotiation.

## 2. Architecture

Two parties on the wire:

- **Observed Agent** — the LLM-backed system being monitored. Implements ACS endpoints (or the stdio analog) and sends hook traffic to the Guardian.
- **Guardian Agent** — the policy enforcement point. Two internal layers:
    - **Deterministic layer** (Cedar/Rego): always runs first.
    - **Agent layer** (LLM): invoked only when the deterministic layer's chain config delegates (`*`, `on_ask`, or pattern-based).

### 2.1 End-to-end flow

```
Observed Agent                                Guardian Agent
══════════════                                ══════════════
     │                                              │
     │ 1. Hook fires; framework builds JSON-RPC      │
     │ 2. Send (HTTP POST or stdio write)            │
     ├──────────────────────────────────────────────>│
     │                                              │ 3. Validate envelope, signature, replay
     │                                              │ 4. Load SessionContext, Intent
     │                                              │ 5. Deterministic layer evaluates
     │                                              │ 6. If delegated, agent layer reasons
     │                                              │ 7. Build decision envelope
     │ 8. Receive response                           │
     │<──────────────────────────────────────────────┤
     │ 9. Enforce decision (allow/deny/modify/ask/defer)
     │ 10. Audit entry written to SessionContext
```

A worked example appears in [ACS in Action](../../topics/ACS_in_action_example.md).

## 3. Wire Format

| Element | Choice |
|---|---|
| Envelope | JSON-RPC 2.0, with top-level `acs_version` |
| Transports | HTTP(S) and stdio (Content-Length framing, UTF-8) |
| Method namespaces | `steps/*`, `protocols/A2A/*`, `protocols/MCP/*`, `agbom/*`, `system/*`, `handshake/*`, `trace/*` (reserved) |
| Wrapped methods | `protocols/MCP/*` is the canonical v0.1 namespace for MCP wrapping (e.g. `protocols/MCP/tools/call`). The `wrapped:` prefix is an alternative explicit-version form for deployments that pin a specific protocol version on the wire (e.g. `wrapped:mcp-2025-06-18/tools/call`). Both are valid; `protocols/*` is preferred. A2A wrapping deferred to v0.2. |
| Error code range | `-32000` to `-32099` reserved for ACS |
| Response shape | Discriminated union: `{ "type": "final", ... }` |
| Forward compat | Accept `X.Y.Z` matching major version; ignore unknown fields |

Streaming and notifications are not supported in v0.1.0. Batching is permitted as standard JSON-RPC 2.0 — Guardians SHOULD accept array-shaped requests and return an array of correlated responses — but ACS does not add atomicity, ordering, or cross-request dependency semantics in v0.1. Each request in a batch is evaluated independently, in declared order, with each carrying its own `request_id` and (if signed) its own signature. A Guardian that does not support batching MUST return `-32600 Invalid Request` for array-shaped inputs so the Observed Agent can fall back to sequential requests.

The full envelope schemas are [`request-envelope.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/request-envelope.json) and [`response-envelope.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/response-envelope.json).

## 4. Capability Negotiation Handshake

Required at session start, before any hook traffic. Wire method: `handshake/hello`. Schema: [`handshake.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/handshake.json) (`$defs/ClientHello` and `$defs/ServerHello`).

**Observed Agent → Guardian Agent (ClientHello):** `acs_versions_supported`, `methods_implemented`, `transports_supported`, `max_payload_size_bytes`, `provenance_producer`, `wrapped_protocols`, `profiles_supported` (conformance profiles the client implements; see [Conformance](../conformance.md)), `approver_types_supported` (which approver types the client can route an `ASK` disposition to; absent/empty declares no `ASK` handling — see [§9.2](#92-approver-incapable-clients-normative)).

**Guardian Agent → Observed Agent (ServerHello):** `negotiated_version`, `methods_evaluated`, `selected_transport`, `signature_algorithms_supported`, `timeout_config` (default and per-method), `approver_types_supported`, `policy_requires_provenance`, `agbom_serializations_supported` (Inspect-pillar serialization formats the Guardian renders on request), `trace_emission` (whether the Guardian emits OTel and/or OCSF for the Trace pillar, plus optional OTLP collector endpoint), `profiles_accepted`.

Version mismatch terminates with `UNSUPPORTED_VERSION`. Unknown fields MUST be ignored. If the client declares `provenance_producer: "none"` and the Guardian's `policy_requires_provenance` is true, the Guardian MUST refuse the session at handshake time rather than silently degrading enforcement.

## 5. Hook Taxonomy

Hook details, payloads, and per-hook examples are catalogued on the [Hooks](./hooks.md) page. The native `steps/*` set is:

| # | Method | Trigger |
|---|---|---|
| 1 | `sessionStart` | Session initiation, before any other `steps/*` hook for the `session_id` |
| 2 | `agentTrigger` | Agent activation |
| 3 | `turnStart` | Beginning of an agent turn |
| 4 | `userMessage` | User input received |
| 5 | `agentResponse` | Agent output before reaching the user |
| 6 | `knowledgeRetrieval` | RAG / knowledge lookup |
| 7 | `memoryContextRetrieval` | Memory read |
| 8 | `memoryStore` | Memory write |
| 9 | `toolCallRequest` | Before tool execution |
| 10 | `toolCallResult` | After tool execution, before agent ingestion |
| 11 | `preCompact` | Before context-window compaction; decision-eligible |
| 12 | `postCompact` | After compaction; carries the new summary's payload and provenance |
| 13 | `subagentStart` | A subagent is spawned (in-process delegation) |
| 14 | `subagentStop` | A subagent has terminated |
| 15 | `turnEnd` | End of an agent turn |
| 16 | `sessionEnd` | Session termination, audit finalization |

Wrapped: `protocols/MCP/*` (specified in v0.1; see [Extending MCP](./extend_mcp.md)). The `protocols/A2A/*` namespace is reserved; wrapping specification deferred to v0.2.

Inspect-pillar methods (`agbom/*`): `agbom/snapshot` and `agbom/changed` (see [Inspect](../inspect/README.md)). System methods (`system/*`): `system/ping` (§13). These are not Instrument hooks — they're the wire surface for Inspect and transport-control — but they share the request-envelope shape, and `agbom/*` participates in the SessionContext audit chain.

## 6. Disposition Vocabulary

| Disposition | Meaning | Required fields |
|---|---|---|
| `ALLOW` | Proceed | none (`reasoning` RECOMMENDED when user-visible audit trails are expected) |
| `DENY` | Block | `reasoning` |
| `MODIFY` | Proceed with changes (covers redaction via `modifications.redactions`) | `reasoning`, `modifications` |
| `ASK` | Pause and request approval (substituted with `DEFER` or `DENY` for approver-incapable clients — see [§9.2](#92-approver-incapable-clients-normative)) | `reasoning`, `ask_details` |
| `DEFER` | Verdict not yet reachable | `reasoning`, `defer_details` |

DEFER reasons: `insufficient_context`, `conflicting_policies`, `low_confidence`, `pending_dependency`. DEFER MUST include `resolution_method`, `resolution_timeout_ms`, and `timeout_decision` (default `deny`). Cascading deferrals MUST be bounded per session.

### 6.1 Decision result fields

The decision envelope ([`response-envelope.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/response-envelope.json)) carries a fixed set of fields that compose to support audit, observability, and cross-paradigm enforcement:

| Field | Required | Purpose |
|---|---|---|
| `decision` | yes | The verdict, one of the five dispositions above. |
| `reasoning` | conditional | Single human-renderable explanation. Serves both end-user display and audit/agent-internal consumption; deployments wanting different text per audience SHOULD compose them client-side from `reasoning` + `policy_data` + `reason_codes`. |
| `policy_references` | no | Array of `{policy_id, policy_name, rule_id}` — the rules that fired. A single decision MAY cite multiple entries when several paradigms reject the same action; audit replay walks the list to reconstruct contributions. |
| `reason_codes` | no | Array of machine-readable categorization strings. Free vocabulary in v0.1. UIs and meta-policies SHOULD switch on these rather than parsing reasoning text or rule IDs. |
| `policy_data` | no | Free-form structured payload for paradigm- or policy-specific facts. When multiple paradigms fire, conventionally keyed by paradigm name (`{ "ibac": {...}, "fides": {...}, "aarm": {...} }`). |
| `cited_provenance_ids` | no | Array of `provenance_id`s whose facts drove this decision. Standard top-level surface for "which provenance objects mattered". |
| `modifications` / `ask_details` / `defer_details` | conditional | Disposition-specific payloads. |
| `metadata` | no | ACS-defined evaluator/observability metadata: `evaluator` (`deterministic`/`agent`/`composite`), `evaluator_version`, `evaluation_duration_ms`, `model_id` (required when `evaluator` is `agent` or `composite`), `confidence`. NOT for policy-emitted facts — those go in `policy_data`. |

### 6.2 Paradigm composition

These fields support the v0.1 paradigm targets (FIDES, CaMeL, AARM-style cumulative-context, IBAC) without per-paradigm wire extensions. A FIDES P-T denial cites the violating lineage in `cited_provenance_ids` and exposes the violating-argument path in `policy_data`. An IBAC intent-mismatch DEFER routes through `defer_details` while exposing the requested capability and closest `Intent.parsed` match in `policy_data`. An AARM cumulative-context denial cites `earliest_untrusted_step_id` in `cited_provenance_ids` and reproduces the relevant lookback state in `policy_data`. When a deployment composes paradigms — e.g., IBAC outer + FIDES inner across an A2A boundary — a single decision MAY cite all of them: `policy_references` with one entry per paradigm, `reason_codes` with one or more codes per paradigm, `policy_data` keyed by paradigm.

## 7. Provenance

MAY be attached to data-bearing fields (`Message.content`, `KnowledgeRetrievalResult`, `ToolCallResult.outputs`, `ToolArgumentValue`, A2A payload). Field-level attachment is OPTIONAL — paradigms that do not require information-flow tracking (e.g. pure IBAC) can omit it. When a Provenance object is emitted, all required fields MUST be populated. Schema: [`provenance.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/provenance.json).

| Field | Required | Type | Notes |
|---|---|---|---|
| `provenance_id` | yes | string | Unique within session |
| `origin` | yes | enum | `user_input`, `system`, `tool_output`, `retrieved`, `agent_generated`, `a2a_inbound`, `external` |
| `source_id` | no | string | Identifier within origin |
| `derived_from` | no | string[] | Lineage: array of `provenance_id`s |

### 7.1 Optional `trust` enum

The wire format reserves an OPTIONAL `trust` enum (`trusted`, `untrusted`, `unknown`) so vendor Guardian implementations can carry channel classification in the envelope rather than derive it in policy. v0.1 does not require Guardians to populate it. The expected v0.1 default is for Guardians to derive trust from `origin` + `source_id` against local policy: it keeps the wire format minimal, avoids creating labeled-trusted regions that downstream code stops scrutinizing, and prevents optional-field defaults from ossifying into a de-facto security model. Reserving the field on the wire preserves the option to populate it in a future version (or in a vendor extension today) without a wire-format break.

When a deployment **does** populate `trust`:

- The framework — not the LLM — MUST attach the label, deterministically, based on which channel data crossed. `trust` is never a content judgment and never a producer claim.
- For data with `origin: agent_generated`, the framework MUST compute `trust` as the minimum trust of the entries in `derived_from` (monotonicity rule). No amount of LLM processing launders untrusted data into trusted data.
- Receivers (especially across A2A or multi-Guardian boundaries) MUST treat the field as a hint and re-derive trust against local policy keyed off `origin` + `source_id` rather than honor a remote-asserted label at face value.

### 7.2 Default channel-to-trust mapping

Used both by Guardians that derive trust in policy and by vendor implementations that populate `trust` on the wire. Deployments MAY override in policy but SHOULD record overrides in audit metadata.

| Origin | Default trust |
|---|---|
| `user_input` | `trusted` |
| `system` | `trusted` |
| `tool_output` | `untrusted` |
| `retrieved` | `untrusted` |
| `a2a_inbound` | `untrusted` |
| `external` | `untrusted` |
| `agent_generated` | minimum trust of `derived_from` lineage |

Provenance MUST be populated by deterministic code outside the LLM's output path. Implementations MUST NOT instruct the LLM to produce it. The agent declares `provenance_producer: "framework" | "llm" | "none"` in the handshake; a `none` producer emits no Provenance objects, and Guardians whose policies require Provenance MUST refuse the session at handshake time rather than silently degrading enforcement.

## 8. SessionContext and Intent

State the Guardian Agent maintains across a session. Lives only on the Guardian Agent. The Observed Agent sends only `session_id` and an optional `chain_hash` for verification.

The chain root is established by the first ContextEntry the Guardian writes for a `session_id`, with `previous_hash: null`. This entry is normally produced by `sessionStart`; deployments that do not emit `sessionStart` MAY allow the Guardian to implicitly initialize the chain at the first content-bearing hook, but this is discouraged because it leaves no place to attach session-level identity, policy, or Intent before content enters.

**SessionContext:** `session_id`, `chain_hash` (rolling SHA-256), `entries` (append-only `ContextEntry`), `provenance_summary`, `intent` (optional).

The SessionContext container is intentionally not schematized in v0.1. The wire-visible commitment (`chain_hash`) and the structurally-interesting children (`ContextEntry`, `ProvenanceSummary`, `Intent`) are each defined as portable schemas with normative computation rules; the container that holds them is server-side state and remains implementation-defined. Cross-Guardian interoperability is achieved through the standardized wire artifacts, not through a standardized container format.

### 8.1 ContextEntry

Schema: [`context-entry.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/context-entry.json). Append-only entry in the audit chain.

- **Required:** `entry_id`, `step_id`, `step_type`, `entry_hash`.
- **SHOULD:** `request_hash` (lowercase-hex SHA-256 of the JCS-canonicalized request envelope params; without this the chain commits only to step metadata, not to request content — deployments claiming the **ACS-Audit** profile MUST populate `request_hash`), `timestamp`, `provenance_summary`, `previous_hash` (required for every entry except the first).

Storage representation is implementation-defined; this spec constrains the canonical form used for hashing, not how Guardians store entries internally.

### 8.2 Chain hashing (normative)

`entry_hash = lowercase-hex(SHA-256(content_bytes || prev_hash_bytes))` where:

1. `content_bytes` is the UTF-8 encoding of the RFC 8785 (JCS) canonicalization of the ContextEntry object with `entry_hash` and `previous_hash` fields REMOVED;
2. `prev_hash_bytes` is the raw 32-byte decoding of `previous_hash`, or the empty byte string if `previous_hash` is null/absent (first entry in the session);
3. `||` denotes byte concatenation.

Conformant Guardians MUST compute `entry_hash` this way; otherwise chains computed by different implementations will not match and cross-Guardian audit comparison breaks. Alternative canonicalization schemes are not permitted in v0.1.

### 8.3 ProvenanceSummary

Schema: [`provenance-summary.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/provenance-summary.json). Optional. Condensed view of provenance facts at the entry level (what entered at this step) and at the session level (cumulative across the session). All fields are OPTIONAL — Guardians populate only what their policies consume. Available v0.1 fields: `origins_seen`, `entry_count`, `entry_count_by_origin`, `earliest_step_id_by_origin`, `max_lineage_depth`. v0.1 carries origin-derived aggregates only; trust-derived aggregates are computed Guardian-internally because v0.1 keeps trust classification in policy. The session-level summary is the monotonic aggregation of entry-level summaries.

### 8.4 Intent

Optional. `raw`, `parsed` (capability list), `parser_provenance` (REQUIRED if `parsed` present; `origin` MUST be `user_input`), `scope_mode`.

**Intent immutability (normative).** Once an Intent is established (via `sessionStart` or the first `agentTrigger` for the session), `Intent.parsed` MUST NOT be modifiable by the runtime LLM, by tool outputs, or by any data crossing an `untrusted` channel. The framework enforces immutability; any modification attempt MUST be ignored or rejected, and SHOULD be recorded as an audit event. The only conformant mechanism for extending `Intent.parsed` within a session is an approver's `intent_extension` returned via the ASK flow (§9). This rule is load-bearing for IBAC's central security claim: the capability set is fixed before untrusted data enters and can grow only through explicit, audited approver action.

### 8.5 Size-based archival (optional)

Guardian Agents MAY archive entries when SessionContext exceeds a configurable byte threshold (suggested 64 KB). Archival MUST preserve `chain_hash`, `provenance_summary`, and `intent`. A mismatched `chain_hash` SHOULD trigger an audit event.

## 9. Escalation / Approver Model

ASK approvers MAY be human, agent, or service. `ask_details.approver = { type, id, endpoint }`. The Approver receives an ACS-shaped request and returns an ACS-shaped decision. Approver authentication is REQUIRED. Guardian MUST verify approver identity against policy.

Single-hop only in v0.1. Approvers MUST NOT return ASK. Quorum and recursive ASK deferred to v0.2.

### 9.1 Intent extension via ASK (normative)

When a Guardian raises ASK because a request is outside `Intent.parsed`, the approver's grant MAY include an `intent_extension` field (see [`ask-details.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/ask-details.json)) containing capabilities to add to `Intent.parsed`. The extension's `scope` selects between `this_request` (capabilities apply only to the in-flight request) and `session` (capabilities are appended to `Intent.parsed` for the remainder of the session).

On `scope: session`, the Guardian MUST:

1. Append the capabilities to `Intent.parsed`.
2. Write a ContextEntry with `step_type: "intent_extension"` recording the approver identity, the granted capabilities, and the originating ASK's `step_id`.
3. Carry the extension's `provenance` forward distinct from the original `parser_provenance` so audits can distinguish parser-derived capabilities from approver-extended ones.

Intent extensions are subject to the session's `scope_mode`: a Guardian operating under `scope_mode: strict` MUST NOT honor extensions that would add capabilities the deployment policy forbids in strict mode. This mechanism is the only conformant path to mutate `Intent.parsed` after Intent is committed.

### 9.2 Approver-incapable clients (normative)

Some Observed Agents — IDE plugins, headless automation, runtimes whose enforcement model is allow/deny only — have no way to route an `ASK` disposition. ClientHello carries an optional `approver_types_supported` array (`human` / `agent` / `service`) declaring which approver types the client can resolve. ServerHello carries the same field declaring which the Guardian can route to.

If the intersection of `ClientHello.approver_types_supported` and `ServerHello.approver_types_supported` is empty (including the case where either side declares no support), the Guardian MUST NOT return `ASK`. The Guardian MUST instead substitute one of:

1. `DEFER` with `timeout_decision: "deny"` — when the underlying issue might resolve through retry, an out-of-band escalation, or a later state change. The deferred verdict still counts toward cascading-deferral limits (§6).
2. `DENY` with `reason_codes: ["approver_unavailable"]` and `reasoning` that names the missing capability — when no recovery path exists.

The choice is policy-driven: deployments SHOULD prefer `DEFER` when the request is potentially recoverable through a different surface, and `DENY` when the action is unconditionally outside the client's reachable authority.

This rule preserves the security guarantee — actions that would have been `ASK`'d in an approver-capable deployment are not silently allowed — while letting clients without approver UX participate in ACS sessions as fully conformant ACS-Core deployments.

## 10. Cryptographic Signatures

Optional at the field level; when signatures are negotiated, the envelope is `{ algorithm, value, key_id }` with the algorithm chosen from the registry below. Supported algorithms are declared per-direction in the handshake.

### 10.1 Algorithm registry

The registry is crypto-agile: the `{ algorithm, value, key_id }` envelope supports any registered algorithm, and the handshake declares which algorithms each side supports. v0.1 prioritizes adoption breadth over cryptographic maximalism — signatures are already field-optional, and a spec that ships without PQC mandates protects more deployments than a spec that mandates PQC and doesn't ship. PQC algorithms from NIST FIPS 203–205 (2024) are registered and available; a future version is expected to promote PQC to RECOMMENDED once ecosystem support matures.

| Algorithm | Class | v0.1.0 status |
|---|---|---|
| `HMAC-SHA256` | Symmetric MAC | RECOMMENDED — shared-secret integrity; simplest deployment path. Sufficient for same-host and trusted-network topologies where the threat is accidental tampering or replay. |
| `ECDSA-P256` | Classical asymmetric | OPTIONAL — strongest current ecosystem support across Java, Node, .NET, HSMs, and major cloud KMS providers. |
| `RSA-PSS-SHA256` | Classical asymmetric | OPTIONAL — legacy interop; deployments with existing RSA PKI. |
| `ML-DSA-65` | PQC, lattice (FIPS 204) | OPTIONAL — ~128-bit post-quantum security; ~3.3 KB signatures. Recommended for deployments shipping PQC libraries today. |
| `ML-DSA-44` | PQC, lattice | OPTIONAL — low-bandwidth profile. |
| `ML-DSA-87` | PQC, lattice | OPTIONAL — high-security profile. |
| `SLH-DSA-128s` | PQC, hash (FIPS 205) | OPTIONAL — algorithmic diversity vs. ML-DSA's lattice assumption. Caution: ~7.8 KB signatures, signing takes hundreds of milliseconds — unsuitable for hot-path Guardian responses without careful latency budgeting. |
| `SLH-DSA-128f` | PQC, hash | OPTIONAL — faster signing; larger signatures. |
| `ML-DSA-65+ECDSA-P256` | Hybrid | OPTIONAL — transitional composite for PQC forward-resistance with classical co-signature. |
| `ML-DSA-65+RSA-PSS-SHA256` | Hybrid | OPTIONAL — transitional composite. |

**PQC migration intent.** The long-term direction is PQC-primary. A future ACS version is expected to promote `ML-DSA-65` to RECOMMENDED and eventually deprecate classical-only algorithms, but the timeline depends on ecosystem readiness — library maturity across Java/Node/.NET, HSM/KMS support breadth, and operational experience at scale. The crypto-agile envelope ensures that migration requires no wire-format changes; only the handshake-negotiated algorithm set shifts.

### 10.2 Hybrid signature value encoding

For any algorithm of the form `<PQC>+<CLASSICAL>`, the `value` field carries the concatenation `len(pqc_sig) || pqc_sig || len(classical_sig) || classical_sig`, where each `len` is a 4-byte big-endian unsigned integer and the whole blob is base64-encoded for wire transit. Verifiers MUST verify both component signatures over the same canonical input; failure of either component is a signature failure. The same `key_id` resolves to a hybrid key descriptor that pins both component public keys.

### 10.3 Replay protection

`request_id` (UUID), `timestamp` (ISO 8601), and optional `nonce` (16–64 bytes). Guardians MUST reject requests whose `timestamp` is more than the handshake-negotiated skew window in the past or future, MUST reject duplicate `request_id` values within the session, and SHOULD reject duplicate `nonce` values within a sliding window the deployment configures.

## 11. Platform / OS Independence

ACS MUST be deployable across IDE, SaaS, on-prem on Linux/Windows/macOS/mobile/browser. Normative:

- Resource identifiers MUST use URI form (`file:///C:/...`, `posix:///etc/...`, `https://...`).
- Capability vocabulary uses abstract names (`filesystem.delete`, `network.egress`, `process.execute`).
- Identity descriptors carry a `type` discriminator (`posix_uid`, `windows_sid`, `oauth_subject`, `cert_subject`, …). Schema owned by the Identity workstream.
- Authentication mechanism declared in handshake; spec mandates none.

## 12. Policy Engine and Agent Layers

### 12.1 Policy engine interface

Spec defines the **interface** to the deterministic-layer engine, not the engine.

**Input:** request envelope + SessionContext + Intent + provenance. **Output:** decision envelope, plus optional `delegate_to: "agent"`.

| Engine | Status |
|---|---|
| OPA / Rego | v0.1 starting reference |
| Cedar | v0.2 fast-follow |

Custom engines plug in by respecting the interface. ACS layers conventions on top: modification format, reasoning format, no external HTTP calls in canonical policies, bundle layout, baseline policy bundle.

### 12.2 Agent layer

Invoked by the deterministic layer's chain config. Receives the same input plus the deterministic layer's intermediate output. Returns a decision envelope.

- Prompt MUST treat untrusted data as data, not instructions. Untrusted fields MUST be wrapped/quoted.
- MUST NOT have access to deterministic-layer policy code.
- Decisions MUST be logged with reasoning, model identifier, confidence (when available).
- Timeouts follow the handshake's `timeout_config`.

OPTIONAL for v0.1.0. Deterministic-only deployments are fully conformant.

## 13. Liveness / System Methods

A liveness method is required for connection-health checks, transport-debugging, and timeout tuning. It carries no enforcement semantics and is not part of the audit chain.

**Method:** `system/ping`. Schema: [`hooks/system-ping.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/system-ping.json).

**Request payload.** Standard ACS envelope with `method: "system/ping"` and `payload: { "echo": "<optional string>" }`.

**Response.** Standard ACS decision envelope with `decision: "allow"` and a `payload` object carrying `{ "status": "ok", "echo": "<request.echo>", "server_timestamp": "<iso-8601>" }`.

**Normative rules:**

- Guardians MUST always return `decision: "allow"` for `system/ping` regardless of policy, signature, or session state. The method does not represent a controllable agent action.
- `system/ping` MUST NOT be written into SessionContext as a ContextEntry; it does not participate in the chain hash.
- `system/ping` MUST NOT require a signature even if the session otherwise requires signatures, so that liveness probing remains possible during signature-rotation or key-resolution failures.
- Connection failure or response timeout for `system/ping` is a transport-level signal that the Observed Agent MAY use to renegotiate transport, re-handshake, or fail over; it MUST NOT be interpreted as an enforcement event.
- `system/ping` is the only method in the `system/*` namespace defined in v0.1.0. The namespace is reserved for future low-level transport/control methods (e.g. `system/handshake_renegotiate` in v0.2).

## 14. Multi-Tenancy

`tenant_id` reserved as an optional envelope field. No isolation rules in v0.1. Per-tenant policy scoping, SessionContext isolation, audit boundaries, and cross-tenant A2A rules deferred to v0.2.

## 15. Out of Scope (Deferred)

| Feature | Deferred to | Reason |
|---|---|---|
| Streaming + wrapped streaming methods | v0.2 | SSE, interruption, chunk-level policy is too much surface |
| Batching atomicity, ordering, cross-request dependencies | v0.2 | Standard JSON-RPC 2.0 batching is permitted in v0.1; ACS-specific atomicity / ordering / dependency rules wait for the streaming spec |
| Sensitivity / four-level timeout model | v0.2 | Categorization-from-facts is non-trivial; v0.1 uses a single handshake-negotiated default timeout |
| Recursive ASK + quorum | v0.2 | Bounded delegation and tie-breaking need careful spec |
| Multi-tenant isolation rules | v0.2 | Touches policy, SessionContext, audit, A2A |
| `protocols/A2A/*` wrapping specification | v0.2 | A2A hook wrapping is reserved (namespace exists); detailed method mapping waits |
| AgBOM federation across A2A peers | v0.2 | Single-agent AgBOM is in v0.1; federated views need an A2A-side discovery method first |
| gRPC, unix_socket transports | v0.2+ | HTTP + stdio cover IDE/SaaS/on-prem in v0.1 |
| PQC as RECOMMENDED default | Future | Promote `ML-DSA-65` once ecosystem readiness justifies it |
| Classical-only signature deprecation | Future | Deprecate classical algorithms once PQC-only is universal |

## 16. Roadmap

| Version | Theme | Highlights |
|---|---|---|
| **v0.1.0** | Baseline + profiles | ACS-Core (mandatory), ACS-Trace, ACS-Inspect/Inspect-Dynamic, ACS-Provenance, ACS-Crypto, ACS-Audit profiles |
| **v0.2.0** | Async + composition | Streaming, wrapped streaming, batching atomicity / ordering / dependency semantics, recursive ASK, quorum, multi-tenant isolation, Cedar binding, connection reuse, sensitivity-tier timeout model, AgBOM federation across A2A peers |
| **v0.3.0+** | Reach + transport | gRPC and unix_socket transports, A2A/MCP `deny`/`modify` extensions, classical-only signature deprecation, full deployment-mode taxonomy |

## 17. Error Handling

ACS uses standard [JSON-RPC 2.0 error codes](https://www.jsonrpc.org/specification#error_object). The `-32000` to `-32099` range is reserved for ACS-specific errors.

| Code | Meaning | Typical use |
|---|---|---|
| `-32700` | Parse error | Invalid JSON payload |
| `-32600` | Invalid Request | Not a valid JSON-RPC Request, or array-shaped input to a Guardian that does not support batching |
| `-32601` | Method not found | The requested ACS method does not exist or is not supported |
| `-32602` | Invalid params | `params` are invalid (wrong type, missing required field) |
| `-32603` | Internal error | Unexpected server error |
| `-32000` to `-32099` | Server error | Reserved for ACS-specific errors (e.g. `UNSUPPORTED_VERSION`, `SESSION_REFUSED`, `REPLAY_DETECTED`) |
