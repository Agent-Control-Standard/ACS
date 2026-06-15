# ACS adapter: Claude Code

A drop-in adapter that wires [Claude Code](https://docs.claude.com/claude-code) hooks to an ACS Guardian. No agent code changes; configuration only.

## What it does

Claude Code fires a hook (e.g. `PreToolUse`) by running a shell command and passing the hook event as JSON on stdin. The command's stdout becomes the hook decision.

This adapter is that command. It:

1. Reads the Claude Code hook event from stdin.
2. Translates it to an ACS JSON-RPC request (see [mapping.md](./mapping.md)).
3. POSTs it to a Guardian endpoint.
4. Translates the ACS decision back to the format Claude Code expects.
5. Emits the translated response on stdout.

## Quick start

```bash
# 1. Run the example Guardian (in one terminal)
python3 example_guardian.py
# [guardian] listening on 127.0.0.1:8787

# 2. Wire the adapter into Claude Code
#    Edit ~/.claude/settings.json (see settings.json.example) and replace
#    /path/to/acs_adapter.py with the absolute path on your machine.

# 3. Test it from the shell (no Claude Code needed)
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /home/user"}}' \
  | ACS_GUARDIAN_URL=http://127.0.0.1:8787/acs python3 acs_adapter.py
# {"decision": "block", "reason": "destructive Bash pattern in: rm -rf /home/user"}
```

## Files

- `acs_adapter.py` — the adapter itself. Stdlib-only. No `pip install` required.
- `example_guardian.py` — a minimal local Guardian for testing. Implements deterministic policy (denies destructive Bash and writes to system paths, allows everything else).
- `settings.json.example` — Claude Code config that wires the adapter into every relevant hook.
- `mapping.md` — Claude Code hook → ACS step method table, plus disposition translation.
- `tests/test_adapter.py` — end-to-end round-trip tests. Run with `python3 -m unittest tests.test_adapter`.

## Configuration

The adapter is configured by environment variables, which `settings.json.example` sets per hook:

| Variable | Default | Purpose |
|---|---|---|
| `ACS_GUARDIAN_URL` | `http://127.0.0.1:8787/acs` | Guardian endpoint to POST requests to. |
| `ACS_SESSION_ID` | derived from `$PWD` | Session id sent on every request. Stable across calls in the same working directory by default. |
| `ACS_DEFAULT_DENY` | `1` | If `1`, deny on Guardian-unreachable or adapter errors (fail-closed). Set to `0` for fail-open with audit. |

## Running the tests

```bash
cd adapters/claude-code
python3 -m unittest tests.test_adapter -v
```

The tests start the example Guardian on a free port, pipe sample Claude Code hook payloads through the adapter, and assert the adapter produces the expected Claude Code-shaped output. 10 tests covering happy path, deny paths, lifecycle hooks, unknown hooks, and fail-closed / fail-open posture.

## What this is not

- A production Guardian. `example_guardian.py` is a teaching artifact with three rules. Production Guardians plug in OPA/Rego, Cedar, or a vendor's policy engine.
- A signed-envelope implementation. The adapter does not HMAC the outbound request body. ACS-Core's baseline integrity requirement (§10) is satisfied at the transport layer (typically mTLS or a signed reverse proxy) for this minimal adapter.
- A full handshake implementation. The adapter assumes the Guardian advertises ACS-Core at the endpoint. A production adapter performs `handshake/hello` at session start and caches the negotiated capabilities.

## Conformance status

| ACS-Core item | Status in this adapter |
|---|---|
| Handshake | Assumed (no per-session negotiation). Production wrapper performs `handshake/hello`. |
| JSON-RPC envelope | ✓ (`request_id`, `timestamp`, `acs_version`, `metadata` populated) |
| Hook taxonomy (6 minimum) | ✓ (`sessionStart`, `userMessage`, `toolCallRequest`, `toolCallResult`, `agentResponse`, `sessionEnd`) |
| Dispositions (ALLOW/DENY/ASK/DEFER) | ✓ on all hooks; MODIFY partial (`PreToolUse` with `parameter_overrides` only) |
| SessionContext | session_id passed every request; Guardian maintains chain_hash |
| Replay protection | ✓ (UUID + timestamp on every request) |
| Baseline integrity | ⚠ deferred to transport layer in this minimal adapter |
| Decision honoring | ✓ (wait for response, apply verdict, configurable fail posture) |
| Liveness `system/ping` | not implemented (SHOULD under slim-Core) |
| Wrapped MCP | not implemented (SHOULD-when-MCP-used; Claude Code's MCP traffic goes through its own mechanism and would need a separate wrapping path) |
