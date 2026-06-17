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
- `tests/test_live.py` — automated live integration test against a real `claude --print` session.
- `tests/example_payloads.md` — masked real-world payload examples showing exactly what Claude Code emits.

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

Test breakdown:
- `tests/test_adapter.py` — 13 round-trip tests against the example Guardian (happy path, deny paths, lifecycle hooks, unknown hooks, fail-closed and fail-open posture).
- `tests/test_envelope_schema.py` — 17 spec-validation tests. Every mapped hook's envelope + payload validates against the canonical v0.1.0 `request-envelope.json` and `hooks/<hook>.json`. Hard-FAILs if the canonical schemas are not present at `$ACS_SPEC_DIR` (default `/tmp/acs-spec-source/specification/v0.1.0`).
- `tests/test_live.py` — 2 live-Claude-CLI tests; require `claude` on PATH.

## What this is not

- A production Guardian. `example_guardian.py` is a teaching artifact with a small destructive-Bash regex set plus a protected-path list. Production Guardians plug in OPA/Rego, Cedar, or a vendor's policy engine.
- A signed-envelope implementation. The adapter does not HMAC the outbound request body. ACS-Core (`docs/spec/conformance.md` §C.4) requires baseline HMAC-SHA256 signing on every envelope. **This is a known gap.** Without it, the adapter does not claim ACS-Core conformance; transport security (mTLS / signed reverse proxy) is necessary but does not satisfy the envelope-signature MUST.
- A full handshake implementation. The adapter assumes the Guardian advertises ACS-Core at the endpoint. A production adapter performs `handshake/hello` at session start and caches the negotiated capabilities.

## Conformance status

Honest, MUST-by-MUST against `docs/spec/conformance.md`:

| ACS-Core item | Status |
|---|---|
| Handshake (`handshake/hello`) | ✓ adapter sends ClientHello on first session call; cached in `~/.cache/acs-adapter-handshake/`. Disable with `ACS_HANDSHAKE=0`. |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema for every mapped hook (`test_envelope_schema.py`); format checking enforces `uuid` and `date-time` |
| Hook taxonomy (6 minimum) | ✓ `sessionStart`, `userMessage`, `toolCallRequest`, `toolCallResult`, `agentResponse`, `sessionEnd` |
| Dispositions (ALLOW/DENY/ASK/DEFER) | ✓ on all hooks; MODIFY partial (`PreToolUse` with `parameter_overrides` only) |
| Unknown-disposition fail posture | ✓ default-deny honored on unknown Guardian verdicts (when `ACS_DEFAULT_DENY=1`); spec-default fail-open path emits audit event |
| SessionContext + published `chain_hash` | ✓ session_id propagated; Guardian computes rolling SHA-256 chain per §8.2 (`tests/test_spec_compliance.py`) |
| Replay protection (`request_id` + `timestamp`) | ✓ adapter sends both; Guardian rejects duplicate `request_id` (REPLAY_DETECTED -32005) and timestamps outside skew window (TIMESTAMP_OUT_OF_WINDOW -32006) per §10.3 |
| Baseline integrity (HMAC-SHA256 signature) | ✓ HKDF-derived per-session key signs every request and response when `ACS_HMAC_SECRET` is set; Guardian rejects unsigned/tampered with SIGNATURE_INVALID -32004 |
| Decision honoring (§6.4) | ✓ adapter blocks on subprocess return; spec-default fail-open posture emits structured `ACS_AUDIT` event on every bypass |
| Liveness `system/ping` | ✓ Guardian implements always-allow ping that bypasses chain/replay/signature checks per §13 |
| `nonce` (optional replay field) | ✗ adapter does not emit `nonce`; the envelope field is OPTIONAL in v0.1 |
| Wrapped MCP `protocols/MCP/*` | ✗ not implemented; Claude Code's MCP traffic flows through its own mechanism and would need a separate wrapping path |
