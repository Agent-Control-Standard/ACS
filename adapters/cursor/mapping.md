# Cursor → ACS hook mapping

Schema source: Cursor's `create-hook` skill (`~/.cursor/skills-cursor/create-hook/SKILL.md`).

Each Cursor hook event maps to an ACS `steps/*` method. The adapter (`acs_adapter.py`) does the translation in both directions.

## Hook event mapping

| Cursor hook | ACS step method | Notes |
|---|---|---|
| `sessionStart` | `steps/sessionStart` | Session bounds. |
| `sessionEnd` | `steps/sessionEnd` | |
| `stop` | `steps/sessionEnd` | Cursor's agent-stop signal. |
| `preToolUse` | `steps/toolCallRequest` | Principal interception point. |
| `postToolUse` | `steps/toolCallResult` | Tool result available. |
| `postToolUseFailure` | `steps/toolCallResult` | Tool failed; treated as a result for ACS purposes. |
| `subagentStart` | `steps/subagentStart` | |
| `subagentStop` | `steps/subagentStop` | |
| `beforeShellExecution` | `steps/toolCallRequest` (tool name = "Shell") | Shell-specific gating; Cursor exposes this distinct from preToolUse. |
| `afterShellExecution` | `steps/toolCallResult` | |
| `beforeMCPExecution` | `steps/toolCallRequest` (tool name = "MCP:`server`:`tool`") | MCP tool gating. |
| `afterMCPExecution` | `steps/toolCallResult` | |
| `beforeReadFile` | `steps/knowledgeRetrieval` | File reads modeled as knowledge retrieval. |
| `afterFileEdit` | `steps/toolCallResult` | File edits surface as tool results. |
| `beforeSubmitPrompt` | `steps/userMessage` | Pre-submit prompt gating. |
| `preCompact` | `steps/preCompact` | Context compaction. |
| `afterAgentResponse` | `steps/agentResponse` | Agent emitted a response. |
| `afterAgentThought` | `steps/agentResponse` | Agent reasoning trace; modeled as an agent emission. |
| `beforeTabFileRead` | `steps/knowledgeRetrieval` | Tab inline-completion file read. |
| `afterTabFileEdit` | `steps/toolCallResult` | Tab inline edit applied. |

## Disposition mapping

Cursor's documented response keys are event-specific. The adapter translates ACS dispositions accordingly:

### Permission events (`preToolUse`, `subagentStart`, `beforeShellExecution`, `beforeMCPExecution`)

| ACS disposition | Cursor output | Notes |
|---|---|---|
| `allow` | `{"permission": "allow"}` | |
| `deny` | `{"permission": "deny", "user_message": reasoning, "agent_message": reasoning}` | Cursor displays user_message in UI; agent_message is fed back to the agent's context. |
| `ask` | `{"permission": "ask", "user_message": reasoning, "agent_message": reasoning}` | |
| `defer` | `{"permission": "ask", ...}` | Cursor has no defer; closest equivalent is ask. |
| `modify` | `{"permission": "allow", "updated_input": parameter_overrides, "user_message": reasoning}` on `preToolUse` only | Other permission events have no documented updated-input field; modify substitutes to deny with audit. |

### `postToolUse`, `postToolUseFailure`, `afterMCPExecution`

| ACS disposition | Cursor output |
|---|---|
| `allow` | `{}` (no output; proceed) |
| (any decision with reasoning) | `{"additional_context": reasoning}` |
| `modify` on `afterMCPExecution` with `modified_content` | `{"updated_mcp_tool_output": modified_content}` |

### `subagentStop`

| ACS disposition | Cursor output |
|---|---|
| `allow` | `{}` |
| `deny` | `{"followup_message": "Subagent denied at stop: " + reasoning}` |

### `beforeSubmitPrompt`

Cursor's `beforeSubmitPrompt` has no documented response keys; the adapter uses **exit code** to signal:

| ACS disposition | Adapter behavior |
|---|---|
| `allow` | exit 0, no output |
| `deny` | exit 2 (Cursor's documented block signal) |
| `ask` / `defer` | exit 2 (substituted to block; pause-resume requires Guardian-side resolution) |

### Lifecycle events (`sessionStart`, `sessionEnd`, `stop`, `preCompact`, `afterAgentResponse`, `afterAgentThought`, `beforeReadFile`, `beforeTabFileRead`, `afterFileEdit`, `afterTabFileEdit`)

**Observation-only.** The adapter emits empty output. Cursor fires these *after* the action / message / file edit has occurred (and `beforeReadFile` returns `{}` even on a denied response — the read still happens), so a Guardian `deny` / `modify` on them cannot undo the side effect or block the message. ACS records the event in the audit chain; enforcement on prompts must be placed at `beforeSubmitPrompt`, enforcement on tools at `preToolUse` / `beforeShellExecution` / `beforeMCPExecution`. ACS-Core §hooks.md describes `agentResponse` as decision-eligible; the framework constraint forces this adapter's mapping to honest observation-only.

## Matchers

Cursor's `hooks.json` supports `matcher` regex per hook entry. The adapter does not require any matcher; the Guardian filters server-side. Use matchers in `hooks.json` only if you want to scope which calls reach the Guardian (a deployment optimization, not a correctness concern).

## Exit codes (Cursor's protocol)

| Exit code | Cursor behavior | When the adapter uses it |
|---|---|---|
| 0 | Success; parse stdout as JSON | Normal case for every event except `beforeSubmitPrompt` |
| 2 | Block (same as deny) | `beforeSubmitPrompt` deny; any event when fail-closed and Guardian unreachable and stdout JSON not viable |
| Other nonzero | Fail open unless `failClosed: true` | Not used by the adapter (errors are converted to deny via posture) |

## failClosed

Cursor's per-hook `failClosed: true` makes Cursor block when the hook crashes, times out, or returns invalid JSON. This is independent of the adapter's `ACS_DEFAULT_DENY` (which controls the adapter's own behavior on Guardian-unreachable errors). Use both in production: `failClosed: true` in `hooks.json` for adapter-level failure, `ACS_DEFAULT_DENY=1` for Guardian-unreachable.

## Conformance posture

The Cursor adapter implements ACS-Core's mandatory floor in the same shape as the Claude Code adapter:

- Handshake: assumed-advertised at the endpoint (production adapter performs `handshake/hello` and caches)
- Hook taxonomy minimum (6): all covered, plus many additional Cursor events
- Dispositions: ALLOW / DENY / ASK supported on permission events; MODIFY supported on `preToolUse`; DEFER → ASK substitution (Cursor has no native defer)
- SessionContext: session_id sent every request
- Replay protection: ✓
- Baseline integrity: deferred to transport layer in this minimal adapter
- Decision honoring: ✓ (Cursor enforces the permission verdict; adapter uses exit-2 where Cursor's protocol uses exit code rather than JSON)
