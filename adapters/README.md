# ACS Adapters

Reference implementations that wire popular agent frameworks to an ACS Guardian. The goal: a framework adopts ACS through **configuration only**, with no agent code changes.

## What is a Guardian?

The **Guardian** is the policy enforcement point: a long-running HTTP service that receives every ACS envelope from the adapter, evaluates it against the deployment's policy, and returns one of five dispositions (allow / deny / modify / ask / defer). It's the "decider"; the adapter is the "messenger."

Two roles in any deployment:

- **Production Guardian** — your real policy engine. Typically OPA/Rego, Cedar, or a vendor SDK plugged in behind an HTTP server that speaks the ACS wire protocol. The adapter doesn't care what's inside; only the wire contract matters.
- **`example-guardian/example_guardian.py`** in this repo — a teaching artifact and test substrate. Implements the full wire protocol (handshake, envelope schema validation, HMAC signing, rolling chain, replay protection, skew rejection, dispositions, `system/ping`) but with a deliberately tiny deterministic policy: denies a short list of destructive Bash patterns + writes to system paths, allows everything else. Useful for local testing; **not for production**.

Production deployments swap the policy code in the example Guardian's `evaluate(method, params)` function with their real engine and keep the wire-protocol scaffolding.

Running the Guardian — terminal window, `launchd`, `systemd`, container — is the operator's responsibility. The adapter expects it to be reachable at `$ACS_GUARDIAN_URL`; if it isn't, the §6.4 fail posture applies and an `ACS_AUDIT` event is emitted.

## ACS-Core conformance check

One command verifies this stack against the ACS-Core baseline **minus full Wrapped MCP**, which is deferred:

```bash
cd adapters
python -m unittest test_acs_core_conformance
```

`test_acs_core_conformance.py` enumerates every ACS-Core MUST from `docs/spec/conformance.md` — handshake, envelope shape, the 6 minimum hooks, all 5 dispositions, rolling chain, replay + skew rejection, HMAC-SHA256 baseline, decision honoring + fail-open audit + audit-cause differentiation, system/ping, and the `protocols/MCP/*` namespace shape. Each test docstring quotes the spec line it falsifies. The suite loads the canonical schemas from `Agent-Control-Standard/ACS` (set `ACS_SPEC_DIR` to point at `specification/v0.1.0/`); schemas missing is a hard FAIL, not a skip — spec validation is non-negotiable. Format checking (`uuid`, `date-time`) is enforced via `rfc3339-validator`.

**Wrapped MCP caveat.** The conformance suite verifies the wire-format shape of `protocols/MCP/*` (envelope validates, Guardian returns a structured response, no crash), but the reference Guardian does **not** implement full MCP request wrapping — incoming MCP requests are routed through the standard `steps/toolCallRequest` path with the tool name reflecting the MCP method, not as the wrapped `protocols/MCP/*` form. Deployments that need full MCP wrapping must extend the Guardian. This is a documented v0.2 deferral; a green conformance run means "ACS-Core baseline **minus** full Wrapped MCP", not "the whole baseline." See `test_acs_core_conformance.py::Core10_WrappedMcp`.

## How adapters work

The adapters are **translators**. Each one speaks its framework's hook protocol on one side and ACS JSON-RPC on the other. The framework's agent code is untouched. The Guardian's policy code is untouched. The adapter is the bilingual layer between them.

### The general pattern (same for all three adapters)

For each event the framework fires:

```
   framework                  adapter                   Guardian
      │                          │                         │
      │  hook event (framework   │                         │
      │  native JSON / call)     │                         │
      │ ───────────────────────► │                         │
      │                          │  ACS JSON-RPC request   │
      │                          │ ──────────────────────► │
      │                          │                         │   evaluate
      │                          │                         │   policy
      │                          │  ACS decision           │
      │                          │ ◄────────────────────── │
      │   decision (framework    │                         │
      │   native response shape) │                         │
      │ ◄─────────────────────── │                         │
      │                          │                         │
      ▼                          ▼                         ▼
   applies the                                          appends
   decision                                           audit chain
```

Six steps:

1. Framework fires its hook with a payload in its own format.
2. Adapter receives that payload, translates to an ACS JSON-RPC request.
3. Adapter POSTs to the Guardian endpoint.
4. Guardian evaluates against policy, returns an ACS decision (`allow` / `deny` / `modify` / `ask` / `defer`).
5. Adapter translates that decision back to whatever the framework expects to receive.
6. Framework applies the decision (run / block / modify the action).

### Concrete walkthrough: Claude Code, ALLOW path

You ask Claude Code to `echo hello`.

For brevity, this walkthrough shows the envelope SHAPES and omits the
HMAC-SHA256 `signature` block on each envelope and the once-per-session
`handshake/hello` round-trip that precedes the first content-bearing
event. Both are present in real envelopes — run `python3 adapters/claude-code/e2e_check.py`
to see verbatim envelopes including signatures.

**Step 1.** Claude Code is about to call its Bash tool. Before it runs, Claude Code's hook system fires `PreToolUse`. Your `settings.json` configures `PreToolUse` to run `python3 acs_adapter.py`. Claude Code spawns that process and pipes the event to stdin:

```json
{
  "session_id": "abc-123",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {"command": "echo hello"},
  "tool_use_id": "...",
  "cwd": "/tmp/...",
  "permission_mode": "default"
}
```

**Step 2.** The adapter reads that JSON, builds an ACS JSON-RPC request conforming to v0.1.0 `request-envelope.json` and `hooks/tool-call-request.json`:

```json
{
  "jsonrpc": "2.0",
  "id": "<uuid>",
  "method": "steps/toolCallRequest",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "<uuid>",
    "timestamp": "2026-06-17T12:34:56.789Z",
    "metadata": {
      "agent_id": "claude-code:a1b2c3d4",
      "session_id": "abc-123",
      "cwd": "/tmp/...",
      "platform": "claude-code"
    },
    "payload": {
      "tool": {"name": "Bash"},
      "arguments": {"command": {"value": "echo hello"}}
    }
  }
}
```

Notice the shape: `acs_version` / `request_id` / `timestamp` / `metadata` live inside `params`, not at the envelope root (the envelope schema's `additionalProperties: false` rejects unknown top-level keys). Each tool argument is wrapped as `{value: ...}` so ACS-Provenance can attach provenance per-argument without changing the schema.

**Step 3.** The adapter POSTs to the Guardian endpoint (`http://127.0.0.1:8787/acs`).

**Step 4.** The Guardian evaluates. Our example Guardian's deterministic policy: `echo hello` doesn't match the destructive-Bash regex. Returns a response conforming to `response-envelope.json`:

```json
{
  "jsonrpc": "2.0",
  "id": "<uuid>",
  "result": {
    "type": "final",
    "acs_version": "0.1.0",
    "request_id": "<uuid>",
    "decision": "allow",
    "chain_hash": "..."
  }
}
```

**Step 5.** The adapter translates back to Claude Code's expected shape:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
```

**Step 6.** Claude Code reads stdout, sees `permissionDecision: "allow"`, executes the Bash tool. You see `hello` printed.

The whole round-trip is ~10 ms. The agent doesn't know any of this happened.

### DENY path differs only in steps 4–6

Same as above, but with `command: "rm -rf /home/u"`:

- **Step 4:** Guardian returns `{"decision": "deny", "reasoning": "destructive Bash pattern in: rm -rf /home/u"}`
- **Step 5:** Adapter emits `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "destructive Bash pattern..."}}`
- **Step 6:** Claude Code reads `permissionDecision: "deny"`, does not execute the Bash tool, and surfaces the reason: *"The command was blocked — a policy denied the Bash tool call, so it never ran."*

### What changes across the three adapters

The general pattern is identical. The framework-specific translation differs:

| | Claude Code | Cursor | NAT |
|---|---|---|---|
| **Where the adapter lives** | Separate shell process spawned per hook | Separate shell process spawned per hook | In-process Python class, same memory space as the agent |
| **How the framework sends the event** | JSON on stdin; event type is a field inside the JSON (`hook_event_name`) | JSON on stdin; event type passed as a CLI argument (one command per event in `hooks.json`) | Python method call: `pre_invoke(context)` with `context.function_context.name` |
| **Native event field names** | `tool_name`, `tool_input`, `tool_response` | `tool_name`, `tool_input`, `tool_output`, `command` (for shell) | `context.function_context.name`, `context.modified_kwargs` |
| **Native allow/deny output** | `{"hookSpecificOutput": {"permissionDecision": "allow"|"deny"}}` on stdout | `{"permission": "allow"|"deny"}` on stdout, or `exit 2` to block | Set `context.action = InvocationAction.SKIP` to block, or raise `ACSGuardianDenied` |
| **Native modify mechanism** | `hookSpecificOutput.updatedInput` | `updated_input` | Mutate `context.modified_kwargs` (input) or `context.output` (output) |
| **Process model** | OS spawns a Python process for every hook event | OS spawns a Python process for every hook event | Zero IPC; everything in the same Python interpreter |

The Guardian-side wire format is **the same** for all three. The adapter is bilingual: it knows the framework's protocol on one side and ACS on the other.

### Decision honoring is a framework property

Every adapter relies on its framework providing the §6.4 guarantee: the framework MUST wait for the verdict and apply it before the action executes. If a framework fired the hook fire-and-forget and continued the action without waiting, the adapter would still send to the Guardian and the audit chain would still record the decision — but the framework wouldn't apply it. That would be non-conformant. None of the three frameworks here does that; how each one delivers the guarantee is in the per-adapter README.

### The key insight

ACS standardizes the wire format and the decision contract. Adapters live where the boundary is: between the framework and the Guardian. Each adapter:

1. Knows the framework's hook protocol (the framework's JSON shape, response field names, exit codes).
2. Knows ACS (always the same).
3. Translates between them.

The framework's agent code is untouched. The Guardian's policy code is untouched. The adapter is the bilingual translator that makes them speak. **One Guardian, one ACS contract, three adapters that translate three different protocols into that contract.** Add a new framework, write a new adapter, the Guardian doesn't change.

---

## Directory layout (identical across all three adapters)

Each adapter follows the same structure. Files differ only where the framework's native naming requires it (config example file extension, etc.):

```
adapters/<framework>/
├── README.md                    # overview + quick start + conformance status
├── acs_adapter.py               # the adapter (same filename across all three)
├── mapping.md                   # framework event → ACS step method table
├── <config>.example             # drop-in framework-native config:
│                                #   claude-code/settings.json.example
│                                #   cursor/hooks.json.example
│                                #   nat/workflow.yml.example
└── tests/
    ├── __init__.py
    ├── test_adapter.py          # unit / integration tests against real types
    ├── test_live.py             # automated live test (Cursor: skipped placeholder pointing at live_verification.md)
    ├── example_payloads.md      # masked real-world payload examples
    └── live_verification.md     # (Cursor only) manual reproduction procedure
```

Plus the shared:

```
adapters/example-guardian/
├── README.md
└── example_guardian.py          # used by all three adapters' tests
```

---

## Contributing a new adapter

1. Create `adapters/<framework-name>/`.
2. Write `mapping.md` documenting how the framework's hook events map to ACS `steps/*` methods, and how the framework's response shape relates to ACS dispositions.
3. (Optional but encouraged) Write the adapter itself, plus tests. The Claude Code adapter is the template.
4. Add a row to the status table above.
5. Open a PR against `Agent-Control-Standard/ACS`.

The bar for "reference implementation" status is: round-trip tests pass against the example Guardian, documented configuration for users, and an explicit conformance posture statement matching the format in the Claude Code adapter's README.
