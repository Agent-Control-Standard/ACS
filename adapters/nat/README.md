# ACS adapter: NVIDIA Agent Toolkit (NAT)

A drop-in middleware that wires [NVIDIA NeMo Agent Toolkit](https://github.com/NVIDIA/NeMo-Agent-Toolkit) to an ACS Guardian. No agent code changes; YAML configuration only.

## What it does

NAT exposes a `Middleware` abstraction that wraps any function — tools, sub-workflows, LLM calls, retrievers, memory operations — at the call site. This adapter is a NAT middleware that:

1. Receives every wrapped call's `InvocationContext` (function name, arguments, output) from NAT's middleware pipeline.
2. Translates it to an ACS JSON-RPC request and POSTs it to a Guardian.
3. Applies the Guardian's verdict by blocking the call (raising `ACSGuardianDenied`, or setting `context.action = InvocationAction.SKIP` on NAT versions that expose it), modifying the arguments (`context.modified_kwargs.update(...)`), or passing through.

## Schema source

The middleware interface, config base class, and registration mechanism are taken directly from NAT's public source (`packages/nvidia_nat_core/src/nat/middleware/`). The adapter is built against and verified with **nvidia-nat-core 1.7.0** (PyPI).

## Quick start

```bash
# 1. Install NAT + adapter
pip install nvidia-nat-core
cp acs_adapter.py /path/in/your/project/

# 2. Run the example Guardian (shared with the Claude Code adapter)
python3 ../example-guardian/example_guardian.py
# [guardian] listening on 127.0.0.1:8787

# 3. Wire into your NAT workflow YAML
cat > workflow.yml <<'EOF'
middleware:
  acs:
    _type: acs_guardian
    guardian_url: http://127.0.0.1:8787/acs
    default_deny: true

function_groups:
  my_tools:
    middleware: [acs]

workflow:
  _type: react_agent
  middleware: [acs]
EOF
```

## Files

- `acs_adapter.py` — the middleware class + config + NAT registration. Stdlib + nvidia-nat-core only.
- `workflow.yml.example` — drop-in NAT workflow YAML wiring the middleware.
- `mapping.md` — NAT lifecycle point → ACS step method table.
- `tests/test_adapter.py` — 7 integration tests against the real NAT API (skipped automatically if NAT is not installed).
- `tests/test_live.py` — 5 live workflow tests exercising NAT's `function_middleware_invoke` orchestration.
- `tests/example_payloads.md` — masked real-world payload examples showing the in-process InvocationContext shape and what the adapter sends to the Guardian.

## How it differs from the Claude Code / Cursor adapters

| Aspect | Claude Code / Cursor | NAT |
|---|---|---|
| Interception mechanism | Shell-command-with-stdin-JSON (process spawn per hook) | In-process Python middleware class (`FunctionMiddleware`) |
| Configuration | `settings.json` / `hooks.json` | NAT workflow YAML `middleware:` block |
| Block mechanism | JSON stdout with deny shape, or `exit 2` | Raise `ACSGuardianDenied` (NAT 1.7.0) or set `InvocationAction.SKIP` (NAT dev) |
| Modify mechanism | Updated input field in JSON response | Mutate `context.modified_kwargs` / `context.output` |
| Lifecycle coverage | Whichever events the framework's hook surface exposes | Every function NAT wraps — tools, LLMs, retrievers, memory, sub-workflows |

## Verification status

| Test | Status | Evidence |
|---|---|---|
| Real NAT integration tests | ✓ 7/7 passing | Tests construct real `InvocationContext` + `FunctionMiddlewareContext`, invoke adapter's `pre_invoke` / `post_invoke` via the actual NAT API, assert allow/deny/modify behavior against a live example Guardian. |
| NAT version tested | nvidia-nat-core 1.7.0 (PyPI) | |
| Live integration (full NAT workflow) | ⚠ Manual | Spin up a real NAT workflow with this middleware attached and run it; not yet automated in CI. |

## Compatibility

The adapter works across multiple NAT releases by feature-detecting the block mechanism:

- **NAT 1.7.0 (public release):** blocks by raising `ACSGuardianDenied` (NAT documents "Raises: Any exception to abort execution" for `pre_invoke`).
- **NAT dev branch (with `InvocationAction.SKIP`):** prefers setting `context.action = InvocationAction.SKIP` (cleaner, no exception in logs). The adapter detects the symbol's availability at import time.

## Decision honoring (§6.4)

ACS-Core §6.4 requires the framework to wait for the verdict and apply it before the action executes. NAT provides this guarantee via `function_middleware_invoke`: `pre_invoke` must complete before `call_next(...)` runs, so a deny from the Guardian (whether surfaced as a raised exception or as `InvocationAction.SKIP`) is applied before the wrapped function would execute. The adapter relies on this ordering — without it, a Guardian deny would arrive after the side effect.

## Conformance status

**Conformance posture**: the adapter now exposes ACS-Core's 6-hook minimum on its own by combining two NAT integration points: the `FunctionMiddleware` (for `toolCallRequest` / `toolCallResult`) and a lifecycle observer that subscribes to NAT's `IntermediateStepManager` for `WORKFLOW_START` / `WORKFLOW_END` events. Those events fire `sessionStart` + `userMessage` (on workflow start with input) and `agentResponse` + `sessionEnd` (on workflow end with output). The observer is auto-subscribed on the first `pre_invoke` call.

Honest, MUST-by-MUST against `docs/spec/conformance.md`:

| ACS-Core item | Status in this adapter |
|---|---|
| Handshake (`handshake/hello`) | ✓ on first `pre_invoke` (cached per session) |
| JSON-RPC envelope shape (`request-envelope.json`) | ✓ validates against canonical schema (`test_envelope_schema.py`, runs without NAT) |
| Hook taxonomy minimum | ✓ all 6: `sessionStart`, `userMessage`, `toolCallRequest`, `toolCallResult`, `agentResponse`, `sessionEnd`. Lifecycle hooks come from the `IntermediateStepManager` subscription; function hooks from `FunctionMiddleware`. Verified in `tests/test_lifecycle.py`. |
| Dispositions | ALLOW / DENY / MODIFY supported. ASK/DEFER substituted to DENY at the middleware boundary; deployments wanting pause-and-resume should compose with NAT's HITL middleware (`nat.middleware.hitl`). |
| Unknown-disposition fail posture | ✓ |
| Post-tool deny redaction | ✓ `post_invoke` clears `context.output` and sets `acs_post_invoke_redacted=True` per §6.4 output-redaction gate |
| SessionContext + published `chain_hash` | ✓ session_id coerced to UUID; Guardian computes rolling chain |
| Replay protection | ✓ Guardian enforcement; adapter sends UUID `request_id` + ISO-8601 `timestamp` |
| Baseline integrity (HMAC-SHA256) | ✓ when `ACS_HMAC_SECRET` is set; signed responses verified by adapter (`pre_invoke` and `post_invoke` reject SIGNATURE_INVALID) |
| Decision honoring (§6.4) | ✓ NAT's middleware contract guarantees the function will not execute if `pre_invoke` raises or sets SKIP — verified in `test_live.py` (deny tests assert `executed["count"] == 0`); fail-open emits `ACS_AUDIT` events |
| Liveness `system/ping` | ✓ Guardian-side |
| `request_id_ref` correlation | ✓ `post_invoke` populates with a deterministic uuid5 derived from session + function + kwargs, linking result to request |

## How NAT's defense middleware composes with this

NAT ships `defense_middleware` (in `nvidia-nat-security`) for prompt-injection and PII checks. The ACS adapter does not replace those — it composes with them. A NAT YAML can list multiple middlewares per group, and they execute in order. Recommended composition: ACS first (policy gate), then NAT defense middleware (content filters), then the function. ACS sees every call; defense filters add content-level checks ACS doesn't model.

## Running the tests

```bash
# Tests require nvidia-nat-core
pip install nvidia-nat-core
cd adapters/nat
python -m unittest tests.test_adapter -v
```

If NAT is not installed, the test class is skipped cleanly (`@unittest.skipUnless`).
