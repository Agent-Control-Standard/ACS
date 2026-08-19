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
| `PreToolUse` with `tool_name="Task"` | `steps/subagentStart` | The Task tool IS Claude Code's subagent spawn, so it routes to the confused-deputy gate (Core floor per PR #21) instead of the generic tool hook. All four required fields are real: `parent_step_id` is this step's own deterministic request_id (the delegation step and the spawn event are the same wire step on this platform), `subagent_session_id` is a uuid5 of the `tool_use_id` under a distinct namespace, `intent_derivation` is `derived_from_parent` (the Task prompt is parent-authored — never `"fresh"`). The Guardian's decision translates back through the normal PreToolUse `permissionDecision` shape. `PostToolUse` for the Task call stays `steps/toolCallResult` (it is honestly the tool's result); the separate `SubagentStop` event maps to `steps/subagentStop`. |
| `PostToolUse` | `steps/toolCallResult` | Fires after the tool runs. `tool_response` carries the output. |
| `SubagentStop` | `steps/subagentStop` | A sub-agent has completed. Best-effort payload: `subagent_session_id` is a deterministic UUID5 derived from the most specific identifier Claude Code exposes (agent transcript path when present); `outcome` is always `completed` (the event carries no failure discriminator); `final_chain_hash` is **omitted** — Claude Code maintains no session chain, and fabricating an integrity value would corrupt the artifact the field exists to produce (optional for chain-less frameworks per PR #21). |
| `Notification` | `steps/agentResponse` | **Observation-only.** Claude Code's `Notification` fires *after* the assistant message is delivered to the user; the framework does not consult the hook return value. The adapter emits the ACS envelope for trace + audit, but a Guardian `deny` / `modify` cannot retroactively block or rewrite a message the user has already seen. ACS-Core §hooks.md describes `agentResponse` as decision-eligible; this adapter's mapping is honest about the framework constraint. |

**Deliberately not mapped — `PreCompact`.** `steps/preCompact` requires `entries_to_compact` (`minItems: 1`) — the step_ids being folded into the summary, which is what the post-compaction provenance lineage references. Claude Code's `PreCompact` event carries no entry list, so an honest payload cannot be built; an empty or fabricated list would defeat the hook's provenance-laundering defense. This is a documented Guardian visibility gap (the adapter's `KNOWN_UNMAPPED` set), not an oversight.

Any other Claude Code hook event reaching the adapter (upstream renames, events wired in `settings.json` that the adapter doesn't know) emits an `unmapped_hook_event` audit line and lets Claude Code proceed — an ungoverned event is recorded as ungoverned, never silently dropped. Unmapped today: `PreToolUseFailure`, `PostToolUseFailure`, `PermissionRequest`, and other lifecycle events with no semantic ACS equivalent in v0.1.0.

## Disposition mapping

| ACS disposition | Claude Code response on `PreToolUse` | Claude Code response on block-shape hooks (`PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`) |
|---|---|---|
| `allow` | `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}` | empty (Claude Code proceeds) |
| `deny` | `…"permissionDecision": "deny", "permissionDecisionReason": "…"` | `{"decision": "block", "reason": "..."}` |
| `modify` | `…"permissionDecision": "allow", "updatedInput": {…}` when `parameter_overrides` present; substituted to `deny` otherwise | `PostToolUse`: `updatedToolOutput` when `modified_content` present, substituted to `block` otherwise |
| `ask` | `…"permissionDecision": "ask"` — **native**; Claude Code surfaces its own approval prompt | substituted to `block` (no approval surface post-hoc) |
| `defer` | substituted to `deny` + `defer_substituted_deny` audit event (no native defer in `permissionDecision`; matches the spec default `timeout_decision: deny`, §6) | substituted to `block` |

ASK is native on `PreToolUse` (`permissionDecision: "ask"`). DEFER has no native equivalent anywhere in Claude Code's hook protocol and substitutes to deny/block, matching §6's default `timeout_decision: deny`; the substitution is recorded as an audit event so the substitution rate is machine-visible. A deployment that needs approver-driven resumption should run ACS-Core's ASK flow at the Guardian layer and have the Guardian return an effective decision before responding to the adapter.

## Conformance posture

The Claude Code adapter implements ACS-Core's mandatory floor. Every row below describes what the code in `acs_adapter.py` actually does — this table drifted from the code once (PR #22 review caught six false claims in it), so treat the code as ground truth and this table as its description:

- Handshake: `handshake/hello` is performed once per session (idempotent via disk cache, `~/.cache/acs-adapter-handshake/`) before the first hook event. The ServerHello's response envelope is signature-verified and bound to the ClientHello before caching; its `on_decision_failure` participates in the effective fail posture (most-restrictive-wins with `ACS_DEFAULT_DENY`). Handshake failures are negative-cached for a short TTL so a dead Guardian costs one timeout, not one per event. `ACS_HANDSHAKE=0` disables.
- Dispositions: ALLOW / DENY / ASK are honored natively on `PreToolUse` (`permissionDecision`); MODIFY via `updatedInput` when `parameter_overrides` is present; DEFER substitutes to deny with an audit event. **Post-execution and lifecycle hooks (`PostToolUse`, `Notification → agentResponse`, `Stop`, `SessionEnd`, `SubagentStop`) are observation-only**: Claude Code fires them after the action / message / session has completed; a Guardian `deny` cannot undo the side effect. Deployments needing pre-delivery gating must place the gate at `UserPromptSubmit` for prompts or `PreToolUse` for tools.
- Session context: `session_id` comes from Claude Code's own hook event field on every request; the Guardian-side audit chain accumulates against it. `agent_id` is `ACS_AGENT_ID` when set, else derived as `claude-code:<sha8(cwd)>`.
- Replay protection: `request_id` (UUID) and `timestamp` are populated on every request. `PreToolUse` request_ids are deterministic (UUID5 of Claude Code's `tool_use_id`) so the matching `PostToolUse` can cite `request_id_ref`.
- Baseline integrity: HMAC-SHA256 per §10 over the RFC 8785 (JCS) canonical envelope, with an HKDF-derived per-session key from `ACS_HMAC_SECRET_FILE` / `ACS_HMAC_SECRET`. `rfc8785` is a hard dependency (no fallback canonicalization — §10 permits none). Responses are signature-verified AND bound to their request (`id` + `request_id`); a mis-bound or badly-signed response fails closed regardless of posture. Without a secret the adapter runs unsigned and says so with a loud `unsigned_mode` audit event.
- Decision honoring: the fail posture defaults to `proceed` (fail-open with audit event), matching §6.4's default. `ACS_DEFAULT_DENY=1` or a ServerHello `on_decision_failure: deny` flips it to fail-closed (most-restrictive-wins). Guardian **refusals** (`SIGNATURE_INVALID`, `REPLAY_DETECTED`, `TIMESTAMP_OUT_OF_WINDOW`, malformed/oversized envelope) always fail closed regardless of posture — a refusal is an alive Guardian rejecting the envelope, and each refusal is attacker-reachable (spec issue #32).
- Audit: every fail-open proceed, refusal, substitution, and unmapped event emits an `ACS_AUDIT` line to stderr and, when `ACS_AUDIT_FILE` is set, appends to that file (0600).
