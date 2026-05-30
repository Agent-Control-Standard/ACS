# Identity

Identity answers who a party is: the Observed Agent, the Guardian, the Approver, and the principal on whose behalf the agent acts. It is an upstream dependency of authorization: a [capability](./capability.md) decision is only as meaningful as the identity it is bound to.

> **Workstream ownership.** The identity descriptor schema is owned by the Identity workstream. This page defines the cross-cutting concept and its boundary with the pillars; the descriptor shapes and any future identity profile live with that workstream.

## Principals and descriptors

A principal is the authenticated party initiating or acting within a session. ACS does not invent an identity format. Identity descriptors carry a `type` discriminator that names the scheme (for example `posix_uid`, `windows_sid`, `oauth_subject`, `cert_subject`), and the descriptor shape follows that scheme.

*Example.* A POSIX deployment carries `{ "type": "posix_uid", "uid": 1000 }`; an OAuth deployment carries `{ "type": "oauth_subject", "sub": "..." }`. ACS reads the discriminator and stays agnostic to the rest.

Three identities are distinct and MUST NOT be conflated:

- **Observed Agent identity**: which agent is under governance.
- **Guardian identity**: which policy authority is deciding.
- **Policy-author identity**: who authored the policy that produced a decision.

## Authentication is deployment-defined

> **No mandated mechanism (normative).** ACS mandates no authentication mechanism. The mechanism in use is declared at handshake. Trust schemes (for example SPIFFE, OIDC, DID, organizational PKI, or quorum signing) are deployment-defined and stay off the core wire contract.

This keeps the adoption floor low: a deployment binds ACS to whatever identity infrastructure it already runs. The future Policy Attestation profile will bind policy-author identity to verifiable signatures using the ACS-Crypto registry, without pulling the trust scheme onto the wire.

## Identity and trust basis

An identity descriptor is itself a fact with a [trust basis](./trust.md). An asserted identity is weaker than one bound by a verified credential or signature. Policy that gates high-impact actions should require an identity at an appropriate rung of that spectrum.

---

**Referenced by**

- **Instrument**, [specification](../spec/instrument/specification.md): `user_identity` at session start; Approver identity verification (§9); identity declared at handshake.
- **Trace**, [extend OCSF](../spec/trace/extend_ocsf.md): agent vs human actors distinguished in emitted events.
- **Inspect**, [AgBOM](../spec/inspect/README.md): peer identity on `a2a_peer` components.
- See also [Agents](./agents.md), [Capability](./capability.md), and [Trust basis](./trust.md).
