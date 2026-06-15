# NVIDIA Agent Toolkit (NAT) → ACS mapping

Schema source: NAT public repo (`packages/nvidia_nat_core/src/nat/middleware/`).

NAT's architecture differs from Claude Code and Cursor: rather than firing events at named lifecycle points, NAT wraps every Function (tool / sub-workflow / LLM / retriever / memory operation / etc.) with a `Middleware` chain. The middleware's `pre_invoke` is called before the function executes, `post_invoke` after.

The ACS adapter is implemented as a `FunctionMiddleware` that, for each wrapped call, emits an ACS step request.

## NAT lifecycle → ACS step method

| NAT concept | ACS step method |
|---|---|
| Tool function `pre_invoke` | `steps/toolCallRequest` |
| Tool function `post_invoke` | `steps/toolCallResult` |
| LLM `pre_invoke` | `steps/toolCallRequest` (tool name = "LLM:`provider`:`model`") |
| LLM `post_invoke` | `steps/toolCallResult` |
| Retriever `pre_invoke` | `steps/knowledgeRetrieval` (the adapter treats `retrievers` as knowledge-retrieval calls when target_function points to a retriever group) |
| Memory read | `steps/memoryContextRetrieval` |
| Memory write | `steps/memoryStore` |
| Sub-workflow invocation | `steps/subagentStart` / `steps/subagentStop` (NAT models sub-workflows as nested functions) |
| Workflow entry | `steps/sessionStart` (when attaching at workflow level with a `sessionStart` semantic — typically configured via `target_function_or_group: <workflow>` plus dispatch logic in the Guardian based on tool name) |

The minimal adapter in `acs_adapter.py` emits `steps/toolCallRequest` and `steps/toolCallResult` for every wrapped function call. The Guardian can dispatch on the tool name to apply different policy. Splitting into separate ACS step methods (e.g. `steps/knowledgeRetrieval` for retriever calls) is a configuration choice handled in the adapter's `pre_invoke` based on `function_context.name`; the example adapter uses a single method to keep the round-trip simple.

## ACS disposition → NAT behavior

| ACS disposition | NAT action |
|---|---|
| `allow` | `pre_invoke` returns `None` (proceed unchanged) |
| `deny` | `pre_invoke` raises `ACSGuardianDenied` (NAT 1.7.0) or sets `context.action = InvocationAction.SKIP` (NAT dev). NAT's runtime documents both: *"Raises: Any exception to abort execution"* and the action-based equivalent. |
| `modify` | If `modifications.parameter_overrides` is present and is a dict, the adapter updates `context.modified_kwargs` in place and returns the context. NAT's runtime invokes the function with the modified kwargs. If `modified_content` is present on a post-tool result, the adapter sets `context.output`. |
| `ask` | Substituted to block at the middleware boundary in v1 (NAT has no native pause primitive at the function-middleware layer). Deployments wanting ASK should compose with NAT's HITL middleware (`nat.middleware.hitl`) and have the Guardian resolve before responding. |
| `defer` | Substituted to block in v1 (same reason). |

## Configuration

Middleware is registered with NAT via the `name=` class kwarg on the config:

```python
class ACSMiddlewareConfig(FunctionMiddlewareBaseConfig, name="acs_guardian"):
    ...
```

NAT picks this up via its `register_middleware` registration mechanism (the adapter ships with `@register_middleware(config_type=ACSMiddlewareConfig)` applied to a factory function).

YAML wiring:

```yaml
middleware:
  acs:
    _type: acs_guardian             # matches the name= kwarg above
    guardian_url: http://127.0.0.1:8787/acs
    default_deny: true
    target_function_or_group: my_tools   # optional; otherwise applied via group/workflow membership
    target_location: input          # NAT-standard field
    session_id: null                # adapter generates one per process

function_groups:
  my_tools:
    middleware: [acs]

workflow:
  _type: react_agent
  middleware: [acs]
```

## Composition with NAT's defense middleware

NAT ships `nvidia-nat-security` with `defense_middleware` for content-level checks (PII, output verification, pre-tool LLM gating). The ACS adapter does NOT replace these — both can be attached to the same group. Ordering is by list position in YAML; place ACS first if you want the policy gate before content filters, last if you want content rewrites to be visible to ACS as the final state.

## Conformance posture

The NAT adapter implements ACS-Core's mandatory floor:

- Hook taxonomy: every wrapped function call surfaces as `toolCallRequest` + `toolCallResult`.
- Dispositions: ALLOW / DENY / MODIFY supported normatively; ASK / DEFER substituted to DENY with audit (HITL composition is the recommended path).
- SessionContext: `session_id` sent on every request.
- Replay protection: `request_id` UUID + timestamp.
- Decision honoring: NAT's middleware contract guarantees the function does not execute if `pre_invoke` raises or sets SKIP.
- Baseline integrity: deferred to transport layer in this minimal adapter.
