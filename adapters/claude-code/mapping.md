# Claude Code → ACS hook mapping

Each Claude Code hook event maps to an ACS `steps/*` method. The adapter (`acs_adapter.py`) does the translation in both directions: Claude Code hook event → ACS JSON-RPC request, ACS decision → Claude Code response.

## Hook event mapping

| Claude Code hook | ACS step method | Notes |
|---|---|---|
| `SessionStart` | `steps/sessionStart` | Session bounds. |
| `SessionEnd` | `steps/sessionEnd` | |
| `Stop` | `steps/sessionEnd` | Claude Code's session-stop signal; also maps to `sessionEnd`. |
| `UserPromptSubmit` | `steps/userMessage` | The `prompt` field carries the user's input. |
| `PreToolUse` | `steps/toolCallRequest` | Fires before the tool runs. Decision gates execution. |
| `PostToolUse` | `steps/toolCallResult` | Fires after the tool runs. `tool_response` carries the output. |
| `PreCompact` | `steps/preCompact` | Memory compaction is about to occur. |
| `PostCompact` | `steps/postCompact` | Compaction has completed. |
| `SubagentStop` | `steps/subagentStop` | A sub-agent has completed. |
| `Notification` | `steps/agentResponse` | **Observation-only.** Claude Code's `Notification` fires *after* the assistant message is delivered to the user; the framework does not consult the hook return value. The adapter emits the ACS envelope for trace + audit, but a Guardian `deny` / `modify` cannot retroactively block or rewrite a message the user has already seen. ACS-Core §hooks.md describes `agentResponse` as decision-eligible; this adapter's mapping is honest about the framework constraint. |

Claude Code hooks not currently mapped (the adapter passes them through unhandled, so Claude Code proceeds): `PreToolUseFailure`, `PostToolUseFailure`, `PermissionRequest`, `WorktreeCreate`, `WorktreeRemove`, `InstructionsLoaded`, `ConfigChange`, `TeammateIdle`, `TaskCompleted`, `MCPElicitation`. Most of these have no semantic ACS equivalent in v0.1.0 and can be added in follow-up PRs.

## Disposition mapping

| ACS disposition | Claude Code response on `PreToolUse` | Claude Code response on other hooks |
|---|---|---|
| `allow` | empty (Claude Code proceeds) | empty |
| `deny` | `{"decision": "block", "reason": "..."}` | `{"continue": false, "stopReason": "..."}` |
| `modify` | `{"decision": "modify", "modifiedInput": ...}` if `parameter_overrides` present | substituted to `block` with audit |
| `ask` | `{"decision": "block", "reason": "approval required: ..."}` | same |
| `defer` | `{"decision": "block", "reason": "deferred: ..."}` | same |

ASK and DEFER are substituted to BLOCK at the adapter layer because Claude Code's hook protocol does not have a native pause-and-resume primitive. A deployment that needs approver-driven resumption should run ACS-Core's ASK flow at the Guardian layer and have the Guardian return an effective decision (typically `allow` after approver consent or `deny` on rejection) before responding to the adapter.

## Conformance posture

The Claude Code adapter implements ACS-Core's mandatory floor:

- Handshake: not negotiated per-call; the adapter assumes the Guardian advertises ACS-Core support at the endpoint. A production deployment should perform `handshake/hello` at session start and cache the result.
- Five dispositions: ALLOW / DENY / ASK / DEFER are honored as above for **pre-execution** hooks (`PreToolUse`, `UserPromptSubmit`). MODIFY is partially honored (only on `PreToolUse` with `parameter_overrides`). **Post-execution and lifecycle hooks (`PostToolUse`, `Notification → agentResponse`, `Stop`, `SessionEnd`) are observation-only**: Claude Code fires them after the action / message / session has completed; a Guardian `deny` on those hooks cannot undo the side effect. The adapter emits the audit envelope; deployments needing pre-delivery gating must place the gate at `UserPromptSubmit` for prompts or `PreToolUse` for tools.
- Session context: the adapter sends `session_id` on every request, derived from the working directory hash unless `ACS_SESSION_ID` is set. Guardian-side audit chain accumulates against that id.
- Replay protection: `request_id` (UUID) and `timestamp` are populated on every request.
- Baseline integrity: not implemented in this minimal adapter (HMAC-SHA256 keying is out of scope for the example). A production adapter wraps `acs_adapter.py`'s outbound request in an HMAC envelope using a session key derived from deployment configuration.
- Decision honoring: the adapter's `_fail()` posture is `deny` by default (`ACS_DEFAULT_DENY=1`) and configurable to `proceed` via env var. Matches §6.4 semantics.
