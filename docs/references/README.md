# References

Background reading that informed the v0.1.0 spec.

## Hook surface analysis

[Hook surfaces across major coding agents](./hook_surfaces.md) — a survey of the lifecycle-hook systems exposed by Anthropic Claude Code, Cursor, OpenAI Codex local clients, GitHub Copilot, and the tool/MCP surfaces of Replit, Tabnine, and Windsurf/Codeium. Includes a consolidated semantic-event matrix, migration notes between vendors, and the OpenAI Responses API + provider webhook distinction.

This survey shaped the ACS hook taxonomy: which events are common-enough across vendors to be normative (`sessionStart`, `userMessage`, `toolCallRequest`/`Result`, `agentResponse`, `sessionEnd`); which are present in some hosts and need first-class treatment (`preCompact`/`postCompact`, `subagentStart`/`Stop`, `turnStart`/`turnEnd`); and which incompatibilities make `DEFER` a load-bearing addition (most non-Claude hosts ignore `ask` today).

## Standards compatibility

[Frameworks and standards for prompt-injection safety](./standards_compatibility.md) — a comparison of CaMeL, FIDES, AARM, IBAC, Conseca, ControlValve, MELON, AgentSentry, LlamaFirewall, and the PROV-AGENT / Flowcept provenance lineage, plus Google's secure-agent guidance, MCP security best practices, OWASP Agentic Top 10, and Chrome's User Alignment Critic.

This analysis underpins the v0.1.0 architectural choices: deterministic mediation as the normative core, scanners and replay defenses as pluggable consumers, and PROV-AGENT-style portable provenance as the lineage substrate. The recommended hook primitives in that document map directly onto the v0.1.0 hook taxonomy.

## IBAC paper

[Intent-Based Access Control for AI Agents (PDF)](../assets/ibac-paper.pdf) — Jordan Potti, 2026. The primary source for IBAC's intent-parse/commit-then-deterministically-authorize pattern, the strict/permissive `scope_mode` distinction, and the `DEFER` / approval flow that v0.1.0's Approver model implements.
