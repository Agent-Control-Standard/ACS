# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Writing and Documentation Standards

**IMPORTANT**: When editing ANY text content (documentation, specifications, blog posts, or code comments), you MUST follow the editorial guidelines in `STYLE.md`.

Before finalizing any text, review against the Editorial Checklist in STYLE.md.

## Project Overview

ACS (Agent Control Standard) is the industry standard for building secure, observable AI agents. It delivers three core capabilities:
- **Inspectability**: Complete visibility into agent components and capabilities
- **Traceability**: Full trace trail with reasoning chains
- **Instrumentability**: Hard controls and policy enforcement

## Development Commands

### Documentation Development
```bash
# Serve documentation locally on port 8000
uv run mkdocs serve

# Build documentation static files
uv run mkdocs build
```

### Python Development
```bash
# Install dependencies using UV (preferred)
uv pip install -e .
```

## Architecture Overview

### Core Framework Components
The ACS framework consists of three interconnected layers:

1. **Instrument Layer** (Hooks)
   - Real-time control points that allow Guardian Agents to permit, deny, or modify agent actions
   - Hooks fire before actions execute, enabling preventive security
   - Core hooks: `agentTrigger`, `message`, `toolCallRequest`, `knowledgeRetrieval`, `memoryStore`
   - Protocol extensions for A2A and MCP communications

2. **Trace Layer** (Events)
   - Comprehensive event emission for all agent decisions and actions
   - Maps to industry standards: OpenTelemetry for observability, OCSF for security events
   - Enables forensic analysis and compliance auditing
   - Events include full context: reasoning chains, data flows, decision trees

3. **Inspect Layer** (AgBOM)
   - Dynamic Agent Bill of Materials exposing components, models, tools, and dependencies
   - Supports CycloneDX, SPDX, and SWID formats
   - Real-time inventory as agents evolve and add capabilities
   - Critical for supply chain security and compliance

### Key Protocol Concepts
- **Observed Agent**: The AI agent being monitored (implements ACS endpoints)
- **Guardian Agent**: Enforces security policies and observability (consumes ACS data)
- **Session**: Scoped interaction unit from activation to completion
- **Step**: Atomic action/decision within agent reasoning process
- **Hook Response**: Guardian's permit/deny/modify decision with optional mutations

### Protocol Architecture
- **Transport**: HTTP(S) with JSON-RPC 2.0 payload format
- **Core Methods**: 
  - Hooks: `steps/*` methods for runtime control
  - Protocols: `protocols/A2A`, `protocols/MCP` for inter-agent communication
  - Inspection: `agbom/*` methods for component discovery
- **Data Objects**: Standardized schemas for Agent, Tool, Model, Resource definitions
- **Standards Integration**: OpenTelemetry spans, OCSF events, SBOM formats

### Important Files
- `specification/ACS/acs_schema.json`: Complete JSON Schema for ACS protocol
- `docs/spec/instrument/specification.md`: Detailed protocol specification
- `docs/spec/instrument/hooks.md`: Available hooks and their triggers
- `docs/spec/trace/events.md`: Event catalog and schemas
- `docs/topics/core_concepts.md`: Fundamental concepts and terminology
- `docs/topics/ACS_in_action_example.md`: Step-by-step implementation example
- `project.owasp.yaml`: OWASP Nest project metadata, validated in CI against `owasp/nest-schema`
- `mkdocs.yml`: Documentation site configuration

### Navigation Structure
The documentation follows this hierarchy:
- **Topics**: High-level concepts and examples
- **Specification**: Technical details divided by layer (Instrument/Trace/Inspect)
- **Implementation Guides**: How to extend existing protocols (MCP, A2A, OpenTelemetry, OCSF)

### Development Setup
This is a documentation-focused project built with:
- **UV** for Python dependency management (replaces pip)
- **MkDocs Material** for local documentation preview

### Hosting (decoupled from this repo)
This repository is the **source of truth for the ACS spec** (schema, hooks, events, AgBOM definitions, written specification). The marketing and docs site at **agentcontrolstandard.org** is built and deployed independently from a separate repository — changes here do not propagate automatically. The `.ai` and `.com` domains redirect to `.org`.

### Contact channels
The repository carries no email addresses, by policy. Community contact is GitHub Discussions, security reporting is GitHub private vulnerability reporting, and Code of Conduct enforcement routes to the OWASP CoC process so that a report about a maintainer does not land with the maintainers. Do not add a contact address to documentation, `project.owasp.yaml`, or the site config. Example addresses in specification documents must use the RFC 2606 reserved domains (`example.com`, `example.net`, `example.org`).

### Schema namespace
Schema `$id` values are based at `https://genai-security-project.github.io/agent-control-standard/schema/<spec-version>/`, not at any of the project domains. The namespace follows the org and repo so that schema identity survives a domain or hosting change. Do not rebase `$id` onto a marketing domain.

`$id` is identity, not a fetch target. Every `$ref` in the package is relative and resolves against the enclosing `$id` base, so the whole set must share one base. Two bases means the relative refs resolve to URIs no `$id` declares, which is the defect fixed in `4fb84c1`. If you add a subschema, give it an `$id` under the same base and keep its refs relative.

The base is not yet served: GitHub Pages is not enabled on this repo, so remote retrieval 404s. Local and file-path validation is unaffected.

`$id` is versioned by **spec** version, not release version. `.github/workflows/sync_version.py` deliberately leaves `$id` alone. See `1af1f92`.

### Roadmap Context
- **v0.1** (Current): Documentation, schemas, and requirements
- **v1**: Reference implementations of instrumentation and Guardian Agent
- **v2**: Full AgBOM implementation with standard mappers
- **v3**: Extended protocol support for A2A/MCP deny/modify operations