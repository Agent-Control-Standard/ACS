# Core Concepts

ACS specifies how an AI agent exposes its behavior so a separate **Guardian Agent** can permit, deny, or modify what the agent does — in real time, with a verifiable audit trail. The agent being monitored is an **Observed Agent**.

## The three pillars

ACS v0.1.0 organizes capabilities into three co-equal pillars:

1. **Instrument** — real-time control points (hooks). Observed Agents send hook traffic to the Guardian; the Guardian returns one of five dispositions (`allow`, `deny`, `modify`, `ask`, `defer`). Hooks fire before actions execute, enabling preventive enforcement. See [Specification](../spec/instrument/specification.md) and [Hooks](../spec/instrument/hooks.md).
2. **Trace** — deterministic event emission. Every hook is also recordable as an OpenTelemetry span and an OCSF event. Decisions are recorded as span events on the parent step span, so the verdict and the action it gates share a parent. See [Trace Events](../spec/trace/events.md).
3. **Inspect** — queryable, dynamic Agent Bill of Materials (AgBOM). The Observed Agent declares its components — models, MCP servers, A2A peers, tools, knowledge sources, memory stores — and reports mutations. See [Inspect](../spec/inspect/README.md).

A v0.1.0-conformant deployment implements **ACS-Core** (the Instrument baseline). Trace, Inspect, field-level Provenance, cryptographic signatures, and strengthened audit chains are organized as [conformance profiles](../spec/conformance.md) declared in the handshake.

## The two parties

- **Observed Agent** — the LLM-backed system being monitored. Sends hook traffic. Enforces decisions.
- **Guardian Agent** — the policy enforcement point. Two internal layers:
    - **Deterministic layer** (OPA/Rego, Cedar): always runs first.
    - **Agent layer** (LLM): invoked only when the deterministic layer's chain config delegates. OPTIONAL in v0.1; deterministic-only deployments are fully conformant.

## Vocabulary

- **Session** — scoped interaction unit, from agent activation to completion. Carries a `session_id`, an append-only audit chain, optional Intent, and a running `chain_hash` (rolling SHA-256).
- **Turn** — one end-to-end loop within a session, marked by `turnStart` and `turnEnd`. Many policies key on per-turn state ("limit tool calls per turn," "no consequential action in N turns after taint").
- **Step** — atomic action or decision: a user message, a tool call, a memory write, a knowledge retrieval. Each step produces a `ContextEntry` in the session's audit chain.
- **Hook Response** — the Guardian's verdict: `allow`, `deny`, `modify` (proceed with changes), `ask` (escalate to an approver), `defer` (verdict not yet reachable).

## Provenance

Every data-bearing field MAY carry a Provenance object: `provenance_id`, `origin` (`user_input`, `system`, `tool_output`, `retrieved`, `agent_generated`, `a2a_inbound`, `external`), `source_id`, `derived_from` (lineage). Provenance is populated by deterministic framework code at channel boundaries, never by the LLM.

v0.1 keeps trust *classification* off the mandatory wire surface: Guardians derive trust from `origin` + `source_id` against local policy. The wire format reserves an OPTIONAL `trust` enum for vendor implementations that elect to carry it; when populated, the **monotonicity rule** applies — `agent_generated` data inherits the minimum trust of its lineage.

Field-level Provenance is required under the **ACS-Provenance** profile and load-bearing for FIDES, CaMeL, and AARM-style enforcement.

## SessionContext and Intent

The Guardian maintains per-session state: the audit chain, the running provenance summary, and (optionally) an Intent. The Observed Agent sends only the `session_id` and an optional `chain_hash` for verification; SessionContext lives only on the Guardian.

**Intent** is the explicit, structured authorization for a session: `raw` (the user's request), `parsed` (a capability list), `parser_provenance`, `scope_mode`. Once an Intent is established, `Intent.parsed` MUST NOT be modifiable by the runtime LLM, by tool outputs, or by any data crossing an `untrusted` channel. Intent extension is permitted only through approver action via the ASK flow. This rule is what makes IBAC's central security claim hold: the capability set is fixed before untrusted data enters and can grow only through explicit, audited approver action.

## Agent environment

| Component | Description | Local | Remote | Protocol |
|---|---|---|---|---|
| User | Direct or indirect human interface | ✓ | ✓ | — |
| Trigger | System event activating the agent (notifications, schedules, A2A inbound) | ✓ | ✓ | — |
| Other Agents | Peer agents | ✓ | ✓ | A2A |
| Memory | Short- or long-term state | ✓ | ✓ | — |
| Knowledge | Files, RAG sources, vector DBs | ✓ | ✓ | MCP |
| Prompts | Saved templates for sub-tasks | ✓ | ✗ | MCP |
| API Tools | REST or function calls | ✓ | ✓ | MCP |
| OS Tools | OS calls or keyboard/mouse manipulation (CUA agents) | ✓ | ✗ | — |
| LLM | Reasoning / sub-task model | ✓ | ✓ | — |

![Agent environment](../assets/agent_env.png "Agent environment")

## A2A and MCP

ACS carries MCP and A2A intact. Wrapped MCP messages flow through `protocols/MCP/*` (e.g. `protocols/MCP/tools/call`). ACS also proposes security extensions for [MCP](../spec/instrument/extend_mcp.md) and [A2A](../spec/instrument/a2a/extend_a2a.md) for native observability support. The `protocols/A2A/*` namespace is reserved in v0.1; the wrapping specification arrives in v0.2.

## Read Next

- [ACS in Action](./ACS_in_action_example.md)
- [Conformance Profiles](../spec/conformance.md)
- [Specification](../spec/instrument/specification.md)
