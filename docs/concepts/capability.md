# Capability

A capability is an abstract permission to do something (`filesystem.delete`, `network.egress`, `process.execute`) independent of the specific tool that exercises it. Capabilities are the vocabulary in which authorization is expressed: [Intent](./intent.md) is a set of them, and a [tool](../spec/inspect/README.md) declares the one it needs.

Expressing authorization in capabilities rather than tool names lets policy reason about *what an action does* rather than *which binary does it*. Two different tools that both egress data are subject to the same `network.egress` policy.

*Example.* A `file.write` tool and a `git.commit` tool both exercise `filesystem.write`. Policy written against the capability governs both, without enumerating tools.

## Capability and Intent

`Intent.parsed` is a capability set: the capabilities authorized for the session. A decision-eligible step that requests a capability outside that set is the central check of intent-based control: the Guardian compares the requested capability against the authorized set and the closest match.

Capabilities enter the authorized set in exactly one way after Intent is fixed: an Approver's `intent_extension` through the ASK flow. See [Intent](./intent.md).

## Capability in the inventory

The Inspect pillar catalogs capability from the supply side: each `tool` component declares its abstract `capability`, and an `agent_capability` component groups the tools, MCP servers, and peers that compose a higher-level ability. The AgBOM is what the agent *can* do; Intent is the subset it is *authorized* to do for the session.

## Capability and identity

A capability is only meaningful against the [identity](./identity.md) it is granted to. Least privilege is the intersection of what the agent may do and what the principal it acts for may do; ACS supplies the capability vocabulary that makes that intersection expressible.

---

**Referenced by**

- **Instrument**, [specification](../spec/instrument/specification.md): the requested-capability check against `Intent.parsed`, exposed in `policy_data` on a mismatch.
- **Inspect**, [AgBOM](../spec/inspect/README.md): `tool.capability` and the `agent_capability` component type.
- See also [Intent](./intent.md), [Identity](./identity.md), and [Agents](./agents.md).
