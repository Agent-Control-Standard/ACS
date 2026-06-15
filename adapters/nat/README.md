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
cp acs_middleware.py /path/in/your/project/

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

- `acs_middleware.py` — the middleware class + config + NAT registration. Stdlib + nvidia-nat-core only.
- `mapping.md` — NAT lifecycle point → ACS step method table.
- `tests/test_adapter.py` — 7 integration tests against the real NAT API (skipped automatically if NAT is not installed).

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

## Conformance status

| ACS-Core item | Status in this adapter |
|---|---|
| Handshake | Assumed (per-session negotiation not implemented in the minimal adapter) |
| JSON-RPC envelope | ✓ |
| Hook taxonomy minimum | ✓ via NAT's function-wrapping (every tool/LLM/retriever call surfaces as a `steps/toolCallRequest` + `steps/toolCallResult` pair) |
| Dispositions | ALLOW (pass-through) / DENY (block) / MODIFY (mutate context.modified_kwargs or context.output) supported. ASK/DEFER substituted to DENY at the middleware boundary; deployments wanting pause-and-resume should compose with NAT's HITL middleware (`nat.middleware.hitl`). |
| SessionContext | session_id sent on every request (auto-generated per process unless configured) |
| Replay protection | ✓ (UUID + timestamp) |
| Baseline integrity | ⚠ Deferred to transport layer in this minimal adapter |
| Decision honoring | ✓ (NAT's middleware contract guarantees the function will not execute if `pre_invoke` raises or sets SKIP) |

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
