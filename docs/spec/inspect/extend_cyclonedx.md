# AgBOM with CycloneDX

!!! info "Work in progress"
    This specification is currently under development. We're working on defining how AgBOM extends SPDX to support AI agent components.
    
    **Want to contribute?** Check out the [GitHub issue](https://github.com/trustworthyagents/aos/issues/22) and join the discussion!

Agent Bill of Material example using CycloneDX

## Example

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2025-05-19T12:00:00Z",
    "tools": [
      {"name": "cyclonedx-python-lib", "version": "6.2.1"}
    ],
    "authors": [
      {"name": "AgentOps Team", "email": "agentops@example.com"}
    ]
  },
  "components": [
    {
      "type": "service",
      "name": "finance-summary-agent",
      "version": "1.2.3", 
      "bom-ref": "urn:agent:finance-summary-agent",
      "properties": [
        {"name": "a2aCardUrl", "value": "https://agent.example.com/.well-known/agent.json"},
        {"name": "languageRuntime", "value": "Python 3.10.9"},
        {"name": "environment.os", "value": "Ubuntu 22.04"},
        {"name": "environment.architecture", "value": "x86_64"},
        {"name": "model", "value": "gpt-4-32k"},
        {"name": "modelContextWindow", "value": "32768"},
        {"name": "memoryBackend", "value": "Pinecone"},
        {"name": "memoryLimitMB", "value": "2048"},
        {"name": "compliance", "value": "SOC2, GDPR"}
      ]
    },
    {
      "type": "tool",
      "name": "WebSearchAPI",
      "version": "v1",
      "bom-ref": "urn:tool:websearchapi", 
      "properties": [
        {"name": "description", "value": "External web search via Bing API"},
        {"name": "endpoint", "value": "https://api.bing.microsoft.com/v7.0/search"},
        {"name": "auth", "value": "API key"},
        {"name": "scope", "value": "read-only"},
        {"name": "timeoutMs", "value": "3000"}
      ]
    },
    {
      "type": "tool",
      "name": "PythonREPL",
      "version": "1.2",
      "bom-ref": "urn:tool:pythonrepl",
      "properties": [
        {"name": "description", "value": "Sandboxed Python evaluator"},
        {"name": "sandbox", "value": "true"}, 
        {"name": "memoryLimitMB", "value": "128"}
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "urn:agent:finance-summary-agent",
      "dependsOn": [
        "urn:tool:websearchapi",
        "urn:tool:pythonrepl"
      ]
    }
  ],
  "signatures": [
    {
      "value": "<base64-encoded-signature>",
      "keyId": "agent-signing-key"
    }
  ]
}
```
