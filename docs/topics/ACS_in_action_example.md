# ACS in Action

A worked example of an Observed Agent calling the `email.send` tool, with a Guardian Agent enforcing IBAC + FIDES policies, emitting a Trace event, and updating the AgBOM. Read [Core Concepts](./core_concepts.md) first if you haven't.

## Sequence

```
Observed Agent          Guardian Agent          Trace sink (OTLP/SIEM)
══════════════          ══════════════          ══════════════════════
  │                          │                          │
  │ 1. handshake/hello       │                          │
  ├─────────────────────────>│                          │
  │ 2. ServerHello           │                          │
  │<─────────────────────────┤                          │
  │ 3. agbom/snapshot        │                          │
  ├─────────────────────────>│                          │
  │                          │ 4. Trace: acs.agbom      │
  │                          ├─────────────────────────>│
  │ 5. allow                 │                          │
  │<─────────────────────────┤                          │
  │ 6. steps/sessionStart    │                          │
  ├─────────────────────────>│ 7. Open chain root       │
  │ 8. allow                 │                          │
  │<─────────────────────────┤                          │
  │ 9. steps/userMessage     │                          │
  ├─────────────────────────>│                          │
  │ 10. allow                │                          │
  │<─────────────────────────┤                          │
  │ 11. steps/toolCallRequest│                          │
  ├─────────────────────────>│ 12. Evaluate IBAC + FIDES│
  │                          │ 13. Trace: acs.decision  │
  │                          ├─────────────────────────>│
  │ 14. allow                │                          │
  │<─────────────────────────┤                          │
  │ 15. Execute tool         │                          │
  │ 16. steps/toolCallResult │                          │
  ├─────────────────────────>│                          │
  │ 17. allow                │                          │
  │<─────────────────────────┤                          │
```

## The decision point: `steps/toolCallRequest`

The Observed Agent has been asked by a user to "summarize Project X status and email it to my manager." The agent has retrieved the status (untrusted, from a knowledge base), composed a body via the LLM (agent_generated, derived from the retrieval), and is about to call `email.send`. The Guardian must decide.

This example shows a deployment that elects to populate the OPTIONAL `trust` field on the wire. An equally-conformant v0.1 deployment would omit `trust` from the Provenance objects and have the Guardian derive the same classification from `origin` + `source_id` against local policy.

### Request

```json
{
  "jsonrpc": "2.0",
  "method": "steps/toolCallRequest",
  "id": "req-001",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-04-30T10:30:00Z",
    "tenant_id": "acme-corp",
    "metadata": {
      "agent_id": "cursor-agent-01",
      "session_id": "abc-123",
      "turn_id": "t-7",
      "platform": "cursor"
    },
    "payload": {
      "tool": "email.send",
      "arguments": {
        "recipient": {
          "value": "manager@company.com",
          "provenance": {
            "provenance_id": "p1",
            "origin": "user_input",
            "trust": "trusted",
            "source_id": "user-12345",
            "derived_from": []
          }
        },
        "body": {
          "value": "Project X summary: ...",
          "provenance": {
            "provenance_id": "p3",
            "origin": "agent_generated",
            "trust": "untrusted",
            "source_id": "llm-gpt-4",
            "derived_from": ["p2"]
          }
        }
      }
    }
  }
}
```

### Decision

The Guardian's deterministic layer evaluates against IBAC (does `email.send` to `manager@company.com` fall inside `Intent.parsed`?) and FIDES (does the trusted-recipient + possibly-tainted-body combination satisfy the P-F flow check?). Both pass.

```json
{
  "jsonrpc": "2.0",
  "id": "req-001",
  "result": {
    "type": "final",
    "acs_version": "0.1.0",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "decision": "allow",
    "reasoning": "Recipient is trusted (user_input); body lineage is untrusted but the trusted recipient + possibly-tainted body combination is permitted by FIDES P-F under acme-baseline-v1.",
    "reason_codes": ["fides_p_f_check_passed", "ibac_capability_match"],
    "policy_references": [
      { "policy_id": "acme-baseline-v1", "rule_id": "allow-trusted-recipients" },
      { "policy_id": "acme-ibac-v1", "rule_id": "email-send-in-intent" }
    ],
    "policy_data": {
      "fides": { "recipient_trust": "trusted", "body_trust": "untrusted", "p_f_passed": true },
      "ibac": { "matched_capability": { "tool": "email.send", "resource": "manager@company.com" } }
    },
    "cited_provenance_ids": ["p1", "p3"],
    "metadata": {
      "evaluator": "deterministic",
      "evaluator_version": "opa-0.65",
      "evaluation_duration_ms": 12
    }
  }
}
```

## What the Guardian also does

The decision above is one of three concurrent obligations:

1. **Permit/deny/modify** — return the decision envelope to the Observed Agent (above).
2. **Trace** — emit an OTel span event `acs.decision` on the parent `gen_ai.tool.call` span, plus an OCSF Detection Finding (2004) when the decision is non-`allow`. See [Trace Events](../spec/trace/events.md).
3. **AgBOM** — `agbom/snapshot` was emitted earlier in the session; if the agent has registered new components since, `agbom/changed` is emitted before any content-bearing hook continues. See [Inspect](../spec/inspect/README.md).

## A denial would look almost identical

If the user's intent had been "summarize Project X" without the "email it" clause, IBAC would have denied — `email.send` is not in `Intent.parsed`. The decision envelope changes only its shape:

```json
{
  "decision": "deny",
  "reasoning": "Tool call email.send falls outside Intent.parsed for session abc-123.",
  "reason_codes": ["ibac_capability_mismatch"],
  "policy_references": [
    { "policy_id": "acme-ibac-v1", "rule_id": "tool-call-must-be-in-intent" }
  ],
  "policy_data": {
    "ibac": {
      "requested_capability": { "tool": "email.send", "resource": "manager@company.com" },
      "closest_match_in_intent": null
    }
  },
  "cited_provenance_ids": ["p1"]
}
```

The Observed Agent receives this verdict, blocks the tool call, and surfaces the reasoning to the user — who can request an [intent extension via ASK](../spec/instrument/specification.md#91-intent-extension-via-ask-normative) if the deployment policy permits.

## Read Next

- [Instrument](../spec/instrument/README.md)
- [Trace](../spec/trace/README.md)
- [Inspect](../spec/inspect/README.md)
- [Conformance Profiles](../spec/conformance.md)
