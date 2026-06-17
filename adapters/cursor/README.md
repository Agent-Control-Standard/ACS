# ACS adapter: Cursor

A drop-in adapter that wires [Cursor](https://cursor.com) hooks to an ACS Guardian. No agent code changes; configuration only.

## What it does

Cursor fires a hook (e.g. `preToolUse`) by running a shell command per the entry in `hooks.json`. The command receives the hook event JSON on stdin and emits JSON on stdout.

This adapter is that command. It:

1. Reads the Cursor hook event from stdin.
2. Translates it to an ACS JSON-RPC request (see [mapping.md](./mapping.md)).
3. POSTs it to a Guardian endpoint.
4. Translates the ACS decision back to the format Cursor expects.
5. Emits the translated response on stdout (or exit-code blocking, per Cursor's protocol).

## Schema source

Hook event names, output field names, exit-code semantics, and matcher behavior are taken from Cursor's own `create-hook` skill documentation (`~/.cursor/skills-cursor/create-hook/SKILL.md`).

## Quick start

```bash
# 1. Run the example Guardian (in one terminal). Reuses the Claude Code one.
python3 ../example-guardian/example_guardian.py

# 2. Configure Cursor (project-level shown; user-level at ~/.cursor/hooks.json)
mkdir -p .cursor
cat > .cursor/hooks.json <<'EOF'
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 /path/to/acs_adapter.py preToolUse",
        "failClosed": true
      }
    ],
    "beforeShellExecution": [
      {
        "command": "ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 /path/to/acs_adapter.py beforeShellExecution",
        "failClosed": true
      }
    ]
  }
}
EOF

# 3. Test from the shell (no Cursor needed)
echo '{"session_id":"x","tool_name":"Bash","tool_input":{"command":"rm -rf /home/u"}}' \
  | ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 acs_adapter.py preToolUse
# {"permission": "deny", "user_message": "destructive Bash pattern in: rm -rf /home/u", ...}
```

## Files

- `acs_adapter.py` — the adapter. Stdlib-only Python. No `pip install` required.
- `hooks.json.example` — drop-in Cursor config wiring the adapter into every relevant hook.
- `mapping.md` — Cursor hook → ACS step method table, plus disposition translation.
- `tests/test_adapter.py` — 13 round-trip tests. Run with `python3 -m unittest tests.test_adapter`.
- `tests/test_live.py` — placeholder; Cursor's live test is the manual procedure in `tests/live_verification.md`.
- `tests/example_payloads.md` — masked real-world payload examples showing exactly what Cursor emits.

The example Guardian (`adapters/example-guardian/example_guardian.py`) is shared across all adapters — same ACS shape on the wire.

## How it differs from the Claude Code adapter

Same architectural pattern (shell-stdin/stdout, JSON in, JSON out), different protocol:

| Aspect | Claude Code | Cursor |
|---|---|---|
| Event dispatch | Single command, event type in `hook_event_name` field | One command per event, event name passed as `argv[1]` |
| Allow/deny field | `hookSpecificOutput.permissionDecision` | `permission` (top-level) |
| Modify input field | `hookSpecificOutput.updatedInput` | `updated_input` |
| Block via exit code | Optional (`exit 2`) | Supported (`exit 2`); `beforeSubmitPrompt` uses exit code rather than JSON output |
| Fail-closed flag | env var `ACS_DEFAULT_DENY` | hook-level `failClosed: true` in `hooks.json`, plus env var |
| Per-event output keys | Mostly uniform via `hookSpecificOutput` | Event-specific (`permission`, `additional_context`, `updated_mcp_tool_output`, `followup_message`, ...) |

The adapter handles all these protocol differences internally; the Guardian sees the same ACS JSON-RPC shape from both.

## Configuration

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://127.0.0.1:8787/acs` | Guardian endpoint |
| `ACS_DEFAULT_DENY` | `1` | Block on Guardian-unreachable or adapter errors. `0` for fail-open. Cursor's per-hook `failClosed: true` is the recommended way to enforce fail-closed at the hook layer. |

The adapter is invoked as:
```
python3 acs_adapter.py <event_name>
```
where `<event_name>` is one of: `sessionStart`, `sessionEnd`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `subagentStart`, `subagentStop`, `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`, `afterMCPExecution`, `beforeReadFile`, `afterFileEdit`, `beforeSubmitPrompt`, `preCompact`, `stop`, `afterAgentResponse`, `afterAgentThought`, `beforeTabFileRead`, `afterTabFileEdit`.

Pass it in the `hooks.json` `command` line.

## Running the tests

```bash
cd adapters/cursor
python3 -m unittest tests.test_adapter -v
```

13 tests exercising every permission event, lifecycle hooks, unmapped events, and fail-closed / fail-open posture. The example Guardian (shared with the Claude Code adapter) is started on a free port for each test class.

## Verification status

| Test | Status |
|---|---|
| Adapter ↔ Guardian round-trip (unit tests) | ✓ 13/13 pass |
| Schema source | Cursor's own `create-hook` skill (`~/.cursor/skills-cursor/create-hook/SKILL.md`) |
| Live Cursor session fires adapter as expected | ⚠ Not yet verified |

Cursor is a desktop application without a documented headless mode. The live integration test (real Cursor session → adapter → Guardian → policy outcome reflected in Cursor's UI) is a manual step a reviewer with Cursor installed should perform. Suggested procedure:

1. Start the example Guardian: `python3 ../example-guardian/example_guardian.py`
2. In a test project, create `.cursor/hooks.json` per the Quick start section above
3. Open the project in Cursor, ask the agent to run a benign Bash command — should succeed
4. Ask it to run `rm -rf /tmp/anywhere` — should be blocked with the Guardian's deny reason visible in Cursor's UI

## Conformance status

Honest, MUST-by-MUST against `docs/spec/conformance.md`:

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ on first session call; cached per-session |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema for every mapped hook (36 tests) with format checking |
| Hook taxonomy (6 minimum) | ✓ all six covered; 18 Cursor events mapped total |
| Dispositions | ALLOW / DENY / ASK supported on permission events. DEFER substituted to ASK (Cursor has no defer). MODIFY supported on `preToolUse` via `updated_input`. |
| Unknown-disposition fail posture | ✓ |
| SessionContext + published `chain_hash` | ✓ session_id coerced to UUID; Guardian computes rolling SHA-256 chain |
| Replay protection | ✓ Guardian enforcement (REPLAY_DETECTED -32005, TIMESTAMP_OUT_OF_WINDOW -32006) |
| Baseline integrity (HMAC-SHA256) | ✓ when `ACS_HMAC_SECRET` is set; SIGNATURE_INVALID -32004 on tamper |
| Decision honoring (§6.4) | ✓ (Cursor blocks on permission deny; adapter uses exit-2 where stdout JSON is not available); fail-open emits `ACS_AUDIT` event |
| Liveness `system/ping` | ✓ Guardian-side |
| Wrapped MCP `protocols/MCP/*` | ⚠ partial — Cursor's `beforeMCPExecution` is mapped to `steps/toolCallRequest`, not to the `protocols/MCP/*` wrapped form. Real wrapping requires forwarding the full MCP request shape, not flattening it; this adapter does not do that. |

### Per-hook honesty table

Cursor does not expose every field the ACS v0.1.0 hook schemas require. Where the schema is strict and Cursor is silent, the adapter emits a deterministic synthetic value to keep the payload schema-valid. **Synthetic values satisfy the schema but do not carry the meaning the spec requires.** A Guardian seeing them gets a placeholder, not a real subagent boundary or compaction record. This is a Cursor schema gap that ACS cannot close on its side.

| Cursor event → ACS hook | Real Cursor data | Synthetic in payload | Semantic gap |
|---|---|---|---|
| `subagentStart` → `steps/subagentStart` | `subagent_id`, `subagent_type` (optional) | `subagent_session_id` (uuid5 of `subagent_id`), `parent_session_id` (uuid5 of session), `parent_step_id` (uuid4), `intent_derivation` (always `derived_from_parent`) | Subagent IDs do not correspond to anything observable on the Cursor side; intent_derivation is a guess |
| `subagentStop` → `steps/subagentStop` | `subagent_id`, optional `outcome` | `final_chain_hash` (`sha256(subagent_id || timestamp)`) | Hash is fabricated; does not commit to any real chain |
| `preCompact` → `steps/preCompact` | `trigger` (optional) | `entries_to_compact` = `[session_id]` (single-element placeholder) | The actual step_ids being compacted are not available |

These hooks are emitted only when Cursor's `hooks.json` wires them to the adapter. Removing them from your `hooks.json` removes the synthetic emission entirely; the gap is in the data, not in the adapter's correctness.
