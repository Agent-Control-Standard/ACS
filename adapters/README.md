# ACS Adapters

Reference implementations that wire popular agent frameworks to an ACS Guardian. The goal: a framework adopts ACS through **configuration only**, with no agent code changes.

## ACS-Core conformance check

One command verifies this whole stack is still ACS-Core conformant:

```bash
cd adapters
python -m unittest test_acs_core_conformance
```

`test_acs_core_conformance.py` enumerates every MUST from `docs/spec/conformance.md` ACS-Core (handshake, envelope shape, the 6 minimum hooks, all 5 dispositions, rolling chain, replay + skew rejection, HMAC-SHA256 baseline, decision honoring + fail-open audit, system/ping, wrapped MCP). Each test docstring quotes the spec line it falsifies. **44/44 pass on this reference implementation.** If you fork and modify the adapters, run this — any fail names the specific MUST you broke, with citation.

## Status

| Adapter | Status | Mapping | Working adapter | Round-trip | Spec-schema | Live |
|---|---|---|---|---|---|---|
| [claude-code](./claude-code/) | Reference implementation | ✓ | ✓ | 13 passed | 17 passed | ✓ `test_live.py` ALLOW + DENY against real `claude --print` |
| [cursor](./cursor/) | Reference implementation | ✓ | ✓ | 13 passed | 36 passed | ✓ Manual procedure in `tests/live_verification.md` (Cursor is a desktop app, no headless mode) |
| [nat](./nat/) | Reference implementation | ✓ | ✓ | 7 passed (require `nvidia-nat-core==1.7.0`) | 6 passed (work without NAT) | ✓ `test_live.py` (5) + `test_lifecycle.py` (2 — lifecycle hooks on workflow boundary) — all require `nvidia-nat-core` |
| [example-guardian](./example-guardian/) | Test substrate (not a production Guardian) | — | — | — | — | 20 spec-compliance tests in `tests/test_spec_compliance.py` covering §4, §6.4, §8.2, §10, §10.3, §13 |

**NAT note:** the adapter now combines `FunctionMiddleware` (for
toolCallRequest/Result) with an `IntermediateStepManager` lifecycle
observer (for sessionStart/userMessage/agentResponse/sessionEnd on
WORKFLOW_START / WORKFLOW_END events). A NAT deployment using this
adapter satisfies ACS-Core's 6-hook minimum on its own. See
`adapters/nat/README.md` and `adapters/nat/tests/test_lifecycle.py`.

**Spec-schema tests** load the canonical schemas from a local clone of
`Agent-Control-Standard/ACS` (set `ACS_SPEC_DIR` to point at
`specification/v0.1.0/`). They are hard-FAIL if the schemas are
missing — not skipped — because spec validation is non-negotiable.
Format checking (`uuid`, `date-time`) is enforced.

**Spec-compliance tests** in `example-guardian/tests/test_spec_compliance.py`
exercise: rolling chain hash per §8.2, REPLAY_DETECTED + TIMESTAMP_OUT_OF_WINDOW
per §10.3, HMAC-SHA256 sign/verify per §10, handshake/hello per §4,
system/ping per §13, and response-envelope schema validation for every
response shape (allow, deny, handshake, ping, error).

---

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

### Why the in-process NAT adapter blocks differently

Claude Code and Cursor both use the shell-stdin pattern: the adapter is a separate process, the framework reads its stdout to learn what to do. Block by emitting a deny-shaped JSON.

NAT is fundamentally different. The adapter runs inside the agent's process as a Python middleware class. When the Guardian denies, the adapter has two options:

1. **Set `context.action = InvocationAction.SKIP`.** NAT's `function_middleware_invoke` checks the action after `pre_invoke` returns and skips the function call. Clean, no exception. Available on the NAT dev branch.

2. **Raise an exception.** NAT's documented "Raises: Any exception to abort execution." Less clean (shows up in logs) but works on every NAT version including the public 1.7.0 release.

The adapter feature-detects which is available and prefers the action-based path.

### The behavior contract

ACS-Core §6.4 requires the framework to **wait for the verdict and apply it before the action executes.** The adapter relies on this:

- For Claude Code and Cursor, the hook subprocess has to return before the tool runs. The shell hook protocol guarantees this — the framework blocks on the subprocess.
- For NAT, `pre_invoke` must complete before `call_next(...)` is invoked. NAT's `function_middleware_invoke` orchestration guarantees this.

If a framework were to fire-and-forget the hook (run it asynchronously and continue the action without waiting), the adapter would still send to the Guardian and the audit chain would still record the decision — but the framework wouldn't actually apply it. That would be non-conformant. None of the three frameworks here does that.

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
