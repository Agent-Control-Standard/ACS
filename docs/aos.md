# Agent Observability Standard

The Agent Observability Standard (AOS) provides specification for building [trustworthy agents](./README.md).
Agents that implement AOS can be deployed with higher trust.
They are instrumentable, traceable and inspectable.
They are an open book 

They have a dynamic bill-of-material, a clear audit trail and hard inline-controls.

<!-- TODO: add diagram -->

Trustworthiness of agents builds upon the foundation of existing standards (MCP and A2A), but provides value regardless. 
It build upon cybersecurity and observability standards including OpenTelemetry, OCSF, CycloneDX, SPDX and SWID.

AOS makes agents trustworthy.

!!! info "Work in progress"
    This page is currently under development.
    
    **Want to contribute?** Check out the [GitHub issue](https://github.com/trustworthyagents/aos/issues/53) and join the discussion!

## Trustworthy agents are

??? example "Init agent with AOS"

    === "LangChain (Python)"

        ```python
        from langchain.agents import initialize_agent, Tool
        from langchain.llms import OpenAI
        from aos import AOSInstrument
        
        # Initialize LLM and tools
        llm = OpenAI(temperature=0)
        tools = [
            Tool(
                name="Search",
                func=search_api,
                description="Search the web for information"
            ),
            Tool(
                name="Calculator", 
                func=calculate,
                description="Perform mathematical calculations"
            )
        ]
        
        # Create agent with AOS instrumentation
        agent = initialize_agent(
            tools, 
            llm, 
            agent="zero-shot-react-description",
            verbose=True
        )
        
        # Wrap with AOS for observability
        aos_agent = AOSInstrument(agent)
        ```

    === "Vercel AI SDK (TypeScript)"

        ```typescript
        import { createAgent } from '@vercel/ai'
        import { AOSInstrument } from '@aos/sdk'
        
        // Define tools
        const tools = {
          search: {
            description: 'Search the web for information',
            parameters: z.object({
              query: z.string()
            }),
            execute: async ({ query }) => searchAPI(query)
          },
          calculate: {
            description: 'Perform mathematical calculations',
            parameters: z.object({
              expression: z.string()
            }),
            execute: async ({ expression }) => evaluate(expression)
          }
        }
        
        // Create agent with AOS instrumentation
        const agent = createAgent({
          model: 'gpt-4',
          tools,
          system: 'You are a helpful assistant'
        })
        
        const aosAgent = new AOSInstrument(agent)
        ```

    === "MCP"

        ```json
        {
          "jsonrpc": "2.0",
          "method": "agent/create",
          "params": {
            "name": "research-assistant",
            "capabilities": {
              "tools": ["search", "calculate"],
              "models": ["claude-3-opus"],
              "protocols": ["mcp", "aos"]
            },
            "aos": {
              "instrumentation": {
                "enabled": true,
                "hooks": ["agentTrigger", "toolCallRequest", "message"]
              },
              "trace": {
                "format": "opentelemetry",
                "endpoint": "https://observability.example.com/v1/traces"
              }
            }
          }
        }
        ```

    === "A2A"

        ```yaml
        # Agent manifest with AOS capabilities
        apiVersion: a2a.io/v1
        kind: Agent
        metadata:
          name: research-assistant
          namespace: production
        spec:
          model:
            provider: anthropic
            name: claude-3-opus
          capabilities:
            - search
            - calculate
          observability:
            aos:
              version: "1.0"
              instrumentation:
                hooks:
                  - agentTrigger
                  - toolCallRequest
                  - message
              trace:
                provider: opentelemetry
                endpoint: https://telemetry.example.com
              inspect:
                format: cyclonedx
                dynamic: true
        ```

### Instrumentable

???+ example "Runtime Hooks"

    **Value**: Hooks to agent runtime and lifecycle events.

    **Description**: Specifies hooks that allow intervention at agent's lifecycle and run-time execution.

    **Standards**: [AOS Instrument](./spec/instrument/README.md).

    === "LangChain (Python)"

        ```python
        from aos import GuardianAgent, PolicyResponse
        
        # Create a Guardian Agent to enforce policies
        guardian = GuardianAgent(
            endpoint="https://guardian.example.com",
            policies=["data-protection", "cost-control"]
        )
        
        # Hook into agent runtime
        @aos_agent.hook("toolCallRequest")
        async def on_tool_call(context):
            # Guardian evaluates the tool call
            response = await guardian.evaluate({
                "hook": "toolCallRequest",
                "tool": context.tool_name,
                "parameters": context.parameters,
                "session": context.session_id
            })
            
            if response.action == "DENY":
                raise PermissionError(f"Tool call denied: {response.reason}")
            elif response.action == "MODIFY":
                # Apply Guardian's modifications
                context.parameters = response.modifications
            
            return response
        
        # Example: Guardian denies sensitive data access
        result = await aos_agent.run("Search for employee SSN records")
            # > PermissionError: Tool call denied: Accessing PII data violates policy
        ```

    === "Vercel AI (TypeScript)"

        ```typescript
        import { GuardianAgent, HookContext } from '@aos/guardian'
        
        // Configure Guardian Agent
        const guardian = new GuardianAgent({
          endpoint: 'https://guardian.example.com',
          policies: ['data-protection', 'cost-control']
        })
        
        // Register hooks for runtime control
        aosAgent.registerHook('toolCallRequest', async (context: HookContext) => {
          const response = await guardian.evaluate({
            hook: 'toolCallRequest',
            tool: context.toolName,
            parameters: context.parameters,
            session: context.sessionId
          })
          
          switch (response.action) {
            case 'DENY':
              throw new Error(`Denied: ${response.reason}`)
            case 'MODIFY':
              context.parameters = response.modifications
              break
          }
          
          return response
        })
        
        // Example: Cost control policy in action
        await aosAgent.run('Generate 1000 images using DALL-E')
        // > Error: Denied: Request exceeds cost threshold ($50 limit)
        ```

    === "MCP"

        ```json
        {
          "jsonrpc": "2.0",
          "method": "aos/registerHook",
          "params": {
            "hook": "toolCallRequest",
            "guardianEndpoint": "https://guardian.example.com/evaluate",
            "policies": ["data-protection", "cost-control"]
          }
        }
        
        // Example hook evaluation request from Guardian
        {
          "jsonrpc": "2.0",
          "method": "guardian/evaluate",
          "params": {
            "hook": "toolCallRequest",
            "context": {
              "tool": "database_query",
              "parameters": {
                "query": "SELECT * FROM customers"
              },
              "session": "sess_123"
            }
          }
        }
        
        // Guardian response
        {
          "jsonrpc": "2.0",
          "result": {
            "action": "MODIFY",
            "modifications": {
              "query": "SELECT id, name FROM customers LIMIT 100"
            },
            "reason": "Limited query to prevent full data exposure"
          }
        }
        ```

    === "A2A"

        ```yaml
        # Available AOS hooks for instrumentation
        
        agentTrigger:
          description: Fires when agent starts processing
          can_modify: true
          can_deny: true
          
        message:
          description: Fires for each message in conversation
          can_modify: true
          can_deny: true
          
        toolCallRequest:
          description: Fires before tool execution
          can_modify: true
          can_deny: true
          
        knowledgeRetrieval:
          description: Fires when accessing knowledge bases
          can_modify: false
          can_deny: true
          
        memoryStore:
          description: Fires when storing to memory
          can_modify: true
          can_deny: true
        ```

### Traceable

???+ example "Comprehensive Audit Logs"

    **Value**: Comprehensive audit logs.

    **Description**: Specifies events that capture AI agent lifecycle and runtime execution. Extends OpenTelemetry and OCSF specs with these properties.

    **Standards**: [AOS Trace](./spec/trace/README.md). Extends [OpenTelemetry](./spec/trace/extend_opentelemetry.md), [OCSF](./spec/trace/extend_ocsf.md).

    === "LangChain (Python)"

        ```python
        from opentelemetry import trace
        from aos.trace import AOSTraceProvider
        
        # Configure OpenTelemetry with AOS extensions
        tracer = trace.get_tracer(
            "research-assistant",
            provider=AOSTraceProvider()
        )
        
        # Agent execution with automatic tracing
        with tracer.start_as_current_span("agent_session") as span:
            span.set_attribute("aos.session.id", "sess_123")
            span.set_attribute("aos.agent.name", "research-assistant")
            
            result = await aos_agent.run("Find recent AI safety papers")
        
        # Trace output includes:
        # - Complete reasoning chain
        # - Tool calls with parameters
        # - Model interactions
        # - Decision points
        ```
        
        ```json
        {
          "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
          "spanId": "00f067aa0ba902b7",
          "operationName": "agent_session",
          "startTime": "2024-01-15T10:30:00Z",
          "attributes": {
            "aos.session.id": "sess_123",
            "aos.agent.name": "research-assistant",
            "aos.reasoning.steps": 3,
            "aos.tools.called": ["web-search", "summarize"]
          },
          "events": [
            {
              "name": "aos.step.reasoning",
              "timestamp": "2024-01-15T10:30:01Z",
              "attributes": {
                "thought": "Need to search for recent AI safety papers",
                "action": "tool_call",
                "tool": "web-search"
              }
            }
          ]
        }
        ```

    === "Vercel AI (TypeScript)"

        ```typescript
        import { OpenTelemetryTracer } from '@aos/trace'
        
        // Configure tracing for TypeScript agent
        const tracer = new OpenTelemetryTracer({
          serviceName: 'research-assistant',
          endpoint: 'https://telemetry.example.com'
        })
        
        // Wrap agent with tracing
        const tracedAgent = tracer.instrument(aosAgent)
        
        // Execute with automatic tracing
        const result = await tracedAgent.run('Find recent AI safety papers')
        
        // Trace includes same comprehensive data as Python example
        ```

    === "MCP"

        ```json
        {
          "jsonrpc": "2.0",
          "method": "aos/trace/emit",
          "params": {
            "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
            "spanId": "00f067aa0ba902b7",
            "event": {
              "type": "agent.execution",
              "timestamp": "2024-01-15T10:30:00Z",
              "attributes": {
                "session.id": "sess_123",
                "agent.name": "research-assistant",
                "reasoning.steps": 3,
                "tools.called": ["web-search", "summarize"]
              }
            }
          }
        }
        ```

    === "A2A"

        ```yaml
        # A2A trace event
        apiVersion: a2a.io/v1
        kind: TraceEvent
        metadata:
          traceId: "4bf92f3577b34da6a3ce929d0e0e4736"
          spanId: "00f067aa0ba902b7"
          timestamp: "2024-01-15T10:30:00Z"
        spec:
          eventType: agent.execution
          agent:
            name: research-assistant
            session: sess_123
          execution:
            reasoningSteps: 3
            toolsCalled:
              - web-search
              - summarize
          observability:
            format: opentelemetry
            endpoint: https://telemetry.example.com
        ```

    === "OCSF"

        ```python
        from aos.trace import OCSFLogger
        
        # Configure OCSF security event logging
        security_logger = OCSFLogger(
            endpoint="https://siem.example.com/ocsf",
            api_key="your-api-key"
        )
        
        # Attach to agent for security events
        aos_agent.attach_logger(security_logger)
        
        # Execute agent - security events logged automatically
        result = await aos_agent.run("Access customer database")
        ```
        
        ```json
        {
          "activity_id": 1,
          "activity_name": "Agent Execution",
          "category_uid": 3,
          "category_name": "Application Activity",
          "class_uid": 3001,
          "class_name": "AI Agent Activity",
          "severity_id": 1,
          "time": 1705318200,
          "metadata": {
            "version": "1.0.0",
            "product": {
              "name": "AOS Agent",
              "vendor_name": "Example Corp"
            }
          },
          "actor": {
            "session": {
              "uid": "sess_123",
              "created_time": 1705318200
            },
            "idp": {
              "name": "research-assistant",
              "uid": "agent_456"
            }
          },
          "aos_extensions": {
            "reasoning_chain": [
              {
                "step": 1,
                "thought": "User wants database access",
                "action": "evaluate_permissions"
              }
            ],
            "tools_invoked": ["database_query"],
            "data_accessed": ["customers.personal_info"],
            "risk_score": 8.5
          }
        }
        ```

    === "Real-time Streaming"

        ```typescript
        import { AOSTraceStream } from '@aos/trace'
        
        // Stream trace events in real-time
        const traceStream = new AOSTraceStream(aosAgent)
        
        traceStream.on('event', (event) => {
          // Log to your observability platform
          console.log(`[${event.timestamp}] ${event.type}:`, event.data)
          
          // Send to security monitoring
          if (event.severity === 'high') {
            alertSecurityTeam(event)
          }
        })
        
        // Enable streaming
        await traceStream.start()
        
        // Example output during agent execution:
        // [2024-01-15T10:30:01Z] session.start: {id: 'sess_789', user: 'alice'}
        // [2024-01-15T10:30:02Z] reasoning.step: {thought: 'Analyzing request...'}
        // [2024-01-15T10:30:03Z] tool.call: {name: 'database_query', risk: 'high'}
        // [2024-01-15T10:30:04Z] security.alert: {reason: 'Sensitive data access'}
        ```

### Inspectable

???+ example "Agent Bill of Materials (AgBOM)"

    **Value**: Dynamic agent-aware bill-of-material.

    **Description**: Specifies properties that capture tools, models and capabilities of an AI agent. Extends SBOM standard specs with these properties – AgBOM. Goes further to add dynamic updates to AgBOM to account for dynamic agent capability discovery.

    **Standards**: [AOS Inspect](./spec/inspect/README.md). Extends [CycloneDX](./spec/inspect/extend_cyclonedx.md), [SPDX](./spec/inspect/extend_spdx.md), [SWID](./spec/inspect/extend_swid.md).

    === "LangChain (Python)"

        ```python
        from aos.inspect import generate_agbom
        
        # Generate Agent Bill of Materials in CycloneDX format
        agbom = generate_agbom(aos_agent, format="cyclonedx")
        
        print(agbom.to_json(indent=2))
        ```
        
        ```json
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.5",
          "version": 1,
          "metadata": {
            "timestamp": "2024-01-15T10:30:00Z",
            "component": {
              "type": "ai-agent",
              "name": "research-assistant",
              "version": "1.0.0"
            }
          },
          "components": [
            {
              "type": "ai-model",
              "name": "gpt-4",
              "version": "2024-01-01",
              "supplier": "OpenAI",
              "properties": [
                {"name": "parameters", "value": "175B"},
                {"name": "context_window", "value": "128000"}
              ]
            },
            {
              "type": "tool",
              "name": "web-search",
              "version": "2.1.0",
              "description": "Search the web for information"
            }
          ]
        }
        ```

    === "Vercel AI (TypeScript)"

        ```typescript
        import { generateAgBOM } from '@aos/inspect'
        
        // Generate AgBOM in CycloneDX format for TypeScript agent
        const agbom = await generateAgBOM(aosAgent, {
          format: 'cyclonedx'
        })
        
        console.log(JSON.stringify(agbom, null, 2))
        // Output matches Python example structure
        ```

    === "MCP Protocol"

        ```json
        {
          "jsonrpc": "2.0",
          "method": "aos/agbom/generate",
          "params": {
            "format": "cyclonedx",
            "agent_id": "research-assistant"
          }
        }
        
        // Response
        {
          "jsonrpc": "2.0",
          "result": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
              "timestamp": "2024-01-15T10:30:00Z",
              "component": {
                "type": "ai-agent",
                "name": "research-assistant",
                "version": "1.0.0"
              }
            },
            "components": [
              {
                "type": "ai-model",
                "name": "claude-3-opus",
                "version": "2024-01-01",
                "supplier": "Anthropic"
              }
            ]
          }
        }
        ```

    === "A2A"

        ```yaml
        # Request AgBOM via A2A
        apiVersion: a2a.io/v1
        kind: AgBOMRequest
        metadata:
          name: research-assistant-agbom
        spec:
          agent: research-assistant
          format: cyclonedx
          includeRuntime: true
        ---
        # Response
        apiVersion: a2a.io/v1
        kind: AgBOM
        metadata:
          name: research-assistant-agbom
          timestamp: "2024-01-15T10:30:00Z"
        spec:
          format: cyclonedx
          version: "1.0.0"
          components:
            - type: ai-agent
              name: research-assistant
              models:
                - name: claude-3-opus
                  version: "2024-01-01"
                  supplier: Anthropic
              tools:
                - name: web-search
                  version: "2.1.0"
        ```

    === "SPDX"

        ```python
        from aos.inspect import generate_agbom
        
        # Generate Agent Bill of Materials in SPDX format
        agbom = generate_agbom(aos_agent, format="spdx")
        
        print(agbom.to_string())
        ```
        
        ```text
        SPDXVersion: SPDX-2.3
        DataLicense: CC0-1.0
        SPDXID: SPDXRef-DOCUMENT
        DocumentName: research-assistant-agbom
        DocumentNamespace: https://example.com/agbom/research-assistant
        Creator: Tool: aos-sdk-1.0
        Created: 2024-01-15T10:30:00Z
        
        # Package: AI Agent
        PackageName: research-assistant
        SPDXID: SPDXRef-Agent
        PackageVersion: 1.0.0
        PackageSupplier: Organization: Example Corp
        PackageDownloadLocation: NOASSERTION
        
        # AI Model Component
        PackageName: gpt-4
        SPDXID: SPDXRef-Model-GPT4
        PackageVersion: 2024-01-01
        PackageSupplier: Organization: OpenAI
        PackageProperty: ModelParameters: 175B
        PackageProperty: ContextWindow: 128000
        
        # Tool Component  
        PackageName: web-search
        SPDXID: SPDXRef-Tool-WebSearch
        PackageVersion: 2.1.0
        PackageDescription: Search the web for information
        ```

    === "Dynamic Discovery"

        ```python
        from aos.inspect import DynamicAgBOM
        import asyncio
        
        # Enable dynamic AgBOM updates
        dynamic_agbom = DynamicAgBOM(aos_agent)
        
        # Subscribe to capability changes
        @dynamic_agbom.on_update
        async def on_capability_change(event):
            print(f"Agent capability changed: {event.change_type}")
            print(f"Component: {event.component}")
            
            # Automatically update AgBOM
            new_agbom = await dynamic_agbom.regenerate()
            
            # Notify security systems
            await notify_security_team(new_agbom)
        
        # Example: Agent discovers new tool at runtime
        await aos_agent.run("I need to analyze this PDF document")
        
        # Output:
        # Agent capability changed: COMPONENT_ADDED
        # Component: {"type": "tool", "name": "pdf-analyzer", "version": "1.2.0"}
        # 
        # New component automatically added to AgBOM
        ```

    === "Real-time Updates"

        ```typescript
        import { DynamicAgBOM, AgBOMEvent } from '@aos/inspect'
        
        // Create dynamic AgBOM monitor
        const dynamicAgBOM = new DynamicAgBOM(aosAgent)
        
        // Listen for capability changes
        dynamicAgBOM.on('update', async (event: AgBOMEvent) => {
          console.log(`Capability ${event.changeType}: ${event.component.name}`)
          
          // Get updated AgBOM
          const currentAgBOM = await dynamicAgBOM.getCurrent()
          
          // Validate against policies
          const validation = await validateAgainstPolicy(currentAgBOM)
          
          if (!validation.approved) {
            // Disable unapproved capability
            await aosAgent.disableComponent(event.component.id)
            console.warn(`Disabled unapproved component: ${event.component.name}`)
          }
        })
        
        // Example output when agent adds new model:
        // Capability ADDED: claude-3-opus
        // Validating against policy...
        // Component approved and active
        ```

## Read Next

- [Core concepts](./topics/core_concepts.md)
- [Instrument](./spec/instrument/README.md)
- [Trace](./spec/trace/README.md)
- [Inspect](./spec/inspect/README.md)