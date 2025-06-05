# AOS Specification

**Version:** `0.1.0`

## 1. Core concepts
- **Guardian Agent**: An agent that monitors other agents behavior for anomalous and risky decisions.
- **Agent**: An agent that implements AOS-compliant HTTP endpoints, sending data and providing visibility into its plans, reasoning and context. Also understands AOS responses and enforces results.
- **Session**: A session is a scoped unit of interaction, starting when an agent is activated (by user or environment) and ending when the task or interaction is complete. The session consists of turns, where turn is a single end to end loop between user and agent.
- **Step**: A step is a single unit of action or decision taken by the agent as part of its reasoning or execution process. It can be a user message,  tool/function call, memory operation (retrieve or store context), knowledge retrieval etc. 
- **A2A Message**: A2A-protocol message captured between agents communication.
- **MCP Message**: MCP-protocol message captured between mcp client and mcp server communication.
- **User**: The user involved in agent/user interaction.

## 2. Transport and Format

### 2.1. Transport Protocol

- AOS communication **MUST** occur over **HTTP(S)**.

### 2.2. Data Format

AOS uses **[JSON-RPC 2.0](https://www.jsonrpc.org/specification)** as the payload format for all requests and responses

- Agent requests and guardian agent responses **MUST** adhere to the JSON-RPC 2.0 specification.
- The `Content-Type` header for HTTP requests and responses containing JSON-RPC payloads **MUST** be `application/json`.


## 3. Standard Data Objects
These objects define the structure of data exchanged within the JSON-RPC methods of AOS.


### 3.1. `Agent` Object



| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Human-readable name of the agent.                                                                                                           |
| `id`                              | `string`                                                           | Yes      | Id of the agent.                                                                                                           |
| `description`                       | `string`                                                           | No      | Human-readable description.                                                             |
| `instructions`                       | `string`                                                           | Yes      | Agent internal instrucions, known as system prompt.                                                             |
| `version`                           | `string`                                                           | Yes      | Agent version string.                                                                                                 |
| `provider`                          | [`AgentProvider`](#311-agentprovider-object)                       | Yes       | Information about the agent's provider.                                                                                                     |
| `model`                           | [`Model`](#312-model-object)                                                           | No      | Agent's underlying LLM.                                                                                                 |
| `tools`                  | [`ToolDefinition`](#32-tooldefinition-object)[]                                                         | No       | Available tools.                                                                                          |
| `mcpServers`                      | [`MCPServer`](#314-mcpserver-object)[]               | No      | Available MCP servers.                                                   |
| `resources`                      | [`Resource`](#315-resource-object)[]               | No      | Available resources.                                                   |
| `organization`                   | [`Organization`](#311-organization-object) | No       | Organization / entity that agent belongs to. |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the agent. |

#### 3.1.1. `AgentProvider` Object

Information about the organization or entity providing the agent.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Human-readable name of the agent provider.                                                                                                           |
| `url`                   | `string` | Yes       | URL for the provider's website/contact. |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the agent provider. |

#### 3.1.2. `Model` Object

Information about LLM associated with the agent.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Human-readable name of the model (LLM).                                                                                                           |
| `id`                              | `string`                                                           | Yes      | Id of the model (LLM).                                                                                                           |
| `provider`                   | [`LlmProvider`](#313-llmprovider-object) | Yes       | The LLM provider. |
| `maxTokens`                   | `integer` | No       | Maximum number of tokens the model is allowed to generate in the response. |
| `contextWindow`                   | `integer` | No       | Total number of tokens (input + output) the model can handle in one request. |
| `stopSequences`                   | `string`[] | No       | 	List of tokens that will stop the generation early (e.g., ["User:", "Agent:"]). |
| `defaultParams`                   | `object` | No       | Default model parameters, such as `temperature`, `topK`, etc. |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the model. |


#### 3.1.3. `LlmProvider` Object

Information about the organization or entity providing the LLM.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Human-readable name of the LLM provider.                                                                                                           |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the LLM provider. |

#### 3.1.4. `MCPServer` Object

Information about the available MCP servers.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Name of the MCP server.                                                                                                           |
| `version`                   |  `string`  | Yes       | Version of the MCP server. |

#### 3.1.5. `Resource` Object

Information about the available resources.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Name of the resource.                                                                                                           |
| `id`                              | `string`                                                           | Yes      | Id of the resource.                                                                                                           |
| `description`                              | `string`                                                           | No      | Resource description.                                                                                                           |
| `content`                              | `string`                                                           | Yes      | Resource content.                                                                                                           |
| `mimeType`                              | `string`                                                            | No      | [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) (e.g., text/plain, image/png). Strongly recommended.                                                                                                           |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the resource. |

### 3.2. `ToolDefinition` Object

Describes the tool schema used by the agent.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Tool name.                                                                                                           |
| `id`                              | `string`                                                           | Yes      | Tool Id.                                                                                                           |
| `description`                              | `string`                                                           | No      | Tool description. Usually used by the LLM to determine on the tool call request.                                                                                                           |
| `type`                              | `string`                                                           | Yes      | The type of the tool. Such as function_call, api_request etc.                                                                                                           |
| `arguments`                              | [`ToolArgumentDefinition`](#321-toolargumentdefinition-object)[] \| `null`                                                            | Yes      | Array of tool arguments. Can be null if the tool has no arguments.                                                                                                           |
| `outputs`                              | [`ToolOutputDefinition`](#322-tooloutputdefinition-object)[] \| `null`                                                           | Yes      | Array of tool outputs. Can be null if the tool has no outputs.                                                                                                           |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the LLM provider. |


#### 3.2.1. `ToolArgumentDefinition` Object

Describes the tool argument schema.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Argument name.                                                                                                           |
| `id`                              | `string`                                                           | No      | Argument Id. This should be used when tool argument can be defined and accessed by Id.                                                                                                          |
| `description`                              | `string`                                                           | No      | Argument description. Usually used by the LLM to determine on argument value.                                                                                                           |
| `type`                              | `string`                                                           | No      | The type of the argument. Allowed values are: `string`, `number`, `boolean`, `object`, `array`, `null`.                                                                                                            |
| `mimeType`                              | `string` \| `null`                                                            | No      | [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) (e.g., text/plain, image/png). Strongly recommended.                                                                                                           |
| `required`                              | `boolean`                                                           | Yes      | Whether the tool argument is required.                                                                                                           |

#### 3.2.2. `ToolOutputDefinition` Object

Describes the tool output schema.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                              | `string`                                                           | Yes      | Output name. This should be used when tool output can be defined and accessed by Id.                                                                                                           |
| `id`                              | `string`                                                           | No      | Output Id. This should be used when tool output can be defined and accessed by Id.                                                                                                          |
| `description`                              | `string`                                                           | No      | Output description. Usually used by the LLM to determine on output value.                                                                                                           |
| `type`                              | `string`                                                           | No      | The type of the argument. Allowed values are: `string`, `number`, `boolean`, `object`, `array`, `null`.                                                                                                            |
| `mimeType`                              | `string` \| `null`                                                            | No      | [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) (e.g., text/plain, image/png). Strongly recommended.                                                                                                           |


### 3.3. `Message` Object

Represents a single communication turn or a piece of contextual information between a user and an agent.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`                              | `string`                                                           | Yes      | Message Id. A unique identifier must be provided for messages in the same session.                                                                                                           |
| `role`                              | `string`                                                           | Yes      | Indicates the sender:  `user`, `agent` or `system`.                                                                                                      |
| `content`            | [`Part[]`](#34-part-union-type) | Yes      | Array of content parts. Must contain at least one part.                          |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the message. |


### 3.4. `Part` Union Type

Represents a distinct piece of content within a `Message`. A `Part` is a union type representing exportable content as either `TextPart`, `FilePart`, or `DataPart`. All `Part` types also include an optional `metadata` field (`Record<string, any>`) for part-specific metadata.


It **MUST** be one of the following:

#### 3.4.1. `TextPart` Object

For conveying plain textual content.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `kind`     | `"text"` (literal)    | Yes      | Identifies this part as textual content.      |
| `text`     | `string`              | Yes      | The textual content of the part.              |
| `metadata` | `Record<string, any>` | No       | Optional metadata specific to this text part. |

#### 3.4.2. `FilePart` Object

For conveying file-based content.


| Field Name | Type                  | Required    | Description                                   |
| :--------- | :-------------------- | :---------- | :-------------------------------------------- |
| `kind`     | `"file"` (literal)    | Yes         | Identifies this part as file content.         |
| `file`     | `FileWithBytes` \| `FileWithUri` | Yes  | Contains the file details and data/reference. |
| `metadata` | `Record<string, any>` | No          | Optional metadata specific to this file part. |

#### 3.4.3. `DataPart` Object

For conveying structured JSON data. Useful for forms, parameters, or any machine-readable information.


| Field Name | Type                  | Required | Description                                                                 |
| :--------- | :-------------------- | :------- | :-------------------------------------------------------------------------- |
| `kind`     | `"data"` (literal)    | Yes      | Identifies this part as structured data.                                    |
| `data`     | `Record<string, any>` | Yes      | The structured JSON data payload (an object or an array).                   |
| `metadata` | `Record<string, any>` | No       | Optional metadata specific to this data part (e.g., reference to a schema). |

### 3.5.1. `FileWithBytes` Object

Represents the data for a file, used within a `FilePart`.


| Field Name | Type     | Required | Description                                                                                                                         |
| :--------- | :------- | :------- | :---------------------------------------------------------------------------------------------------------------------------------- |
| `name`     | `string` | No       | Original filename (e.g., "report.pdf").                                                                                             |
| `mimeType` | `string` | No       | [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) (e.g., `image/png`). Strongly recommended. |
| `bytes`    | `string` | Yes      | Base64 encoded file content.                                                                                                        |

### 3.5.2. `FileWithUri` Object

Represents the URI for a file, used within a `FilePart`.


| Field Name | Type     | Required | Description                                                                                                                         |
| :--------- | :------- | :------- | :---------------------------------------------------------------------------------------------------------------------------------- |
| `name`     | `string` | No       | Original filename (e.g., "report.pdf").                                                                                             |
| `mimeType` | `string` | No       | [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) (e.g., `image/png`). Strongly recommended. |
| `uri`      | `string` | Yes      | URI (absolute URL strongly recommended) to file content. Accessibility is context-dependent.                                        |


### 3.6. `AgentTrigger` Object

Represents the trigger that resulted in agent activation.It can be a recurring trigger or responding to an event. <br>
User prompt is not included and it is included in `Message`. 


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `type`                              | `string`                                                           | Yes      | Type of the trigger. Allowed values: `autonomous`.                                                                                                          |
| `event`                              | [`AgentTriggerEvent`](#361-agenttriggerevent-object)                                                           | Yes      | The triggering event.                                                                                                  |
| `content`            | [`Part[]`](#34-part-union-type) | Yes      | Array of content parts. Must contain at least one part.                          |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the trigger. |

#### 3.6.1. `AgentTriggerEvent` Object


Info about triggering event.   


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `type`                              | `string`                                                           | Yes      | Type of the event. Examples: email, recurring.                                                                                                           |
| `id`                              | `string`                                                           | Yes      | The Id of the triggering event.                                                                                                  |


### 3.7. `Source` Union Type

Represents a source that is used as a reference or citation in the Agent response (`Message`) to justify or explain the output.<br>
A `Source` is a union type representing the cited source as either `FileSource` or `SiteSource`.


It **MUST** be one of the following:

#### 3.7.1. `FileSource` Object
For conveying file source.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `kind`                              | `"file"` (literal)                                                            | Yes      |  Identifies this source as file source.                                                                                                         |
| `id`                              | `string`                                                           | Yes      | The Id of the file. The Id is identical to the `Resource` id in the list of agent's available resources (`resources`) if found.                                                                                                |
| `name`                              | `string`                                                           | Yes      | The name of the file (e.g., report.pdf).                                                                                                  |
| `url`                              | `string`                                                           | No      | The url of the file if the file is available remotely to the agent. For example url to Sharepoint or GoogleDrive.                                                                                                   |


#### 3.7.2. `SiteSource` Object
For conveying site source.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `kind`                              | `"site"` (literal)                                                            | Yes      |  Identifies this source as file source.                                                                                                         |
| `url`                              | `string`                                                           | Yes      | The url of the referenced site.                                                                                                  |

### 3.8. `StepContext` Object

Holds information about the context of agent step

| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `agent`                              | [`Agent`](#31-agent-object)                                                           | Yes      | Holds information about the agent.                                                                                                         |
| `session`                              | [`Session`](#39-session-object)                                                           | Yes      | Holds information about the current conversation / interaction with the agent.                                                                                                  |
| `turnId`            | `string` | Yes      | A unique turn Id in the current session.                          |
| `stepId`                   | `string` | Yes       | A unique step Id in the current turn. |
| `timestamp`                   | `string` (ISO 8601) | Yes       | Timestamp (UTC recommended) when this step was recorded. |
| `user`                   | [`User`](#310-user-object) | No       | The user involved with the agent interaction. Exists if the agent was triggered by a user prompt. |


### 3.9. `Session` Object

Holds information about the session.



| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`                              | `string`                                                           | Yes      | A unique identifier of the session.                                                                                                         |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the session. |

### 3.10. `User` Object

Holds information about the user involved in the interaction with the agent. Used when the agent is triggered by a user prompt.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`                              | `string`                                                           | Yes      | User Id.                                                                                                         |
| `name`                              | `string`                                                           | No      | User name.                                                                                                         |
| `email`                              | `string`                                                           | No      | User email.                                                                                                         |
| `organization`                              | [`Organization`](#311-organization-object)                                                           | Yes      | The organization that the user belong to.                                                                                                         |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the user. |

### 3.11. `Organization` Object

Represents an organization. Used in: `Agent` as the owning organization of the agent, `User` as the organization the user belongs to.


| Field Name                          | Type                                                               | Required | Description                                                                                                                                 |
| :---------------------------------- | :----------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`                              | `string`                                                           | Yes      | Organization Id.                                                                                                         |
| `name`                              | `string`                                                           | No      | Human-readable name of the organization.                                                                                                         |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the organization. |

### 3.12. JSON-RPC Structures

AOS adheres to the standard [JSON-RPC 2.0](https://www.jsonrpc.org/specification) structures for requests and responses.

#### 3.12.1. `JSONRPCRequest` Object

All AOS method calls are encapsulated in a JSON-RPC Request object.

- `jsonrpc`: A String specifying the version of the JSON-RPC protocol. **MUST** be exactly `"2.0"`.
- `method`: A String containing the name of the method to be invoked (e.g., `"steps/knowledge"`, `"messages/mcp"`).
- `params`: A Structured value that holds the parameter values to be used during the invocation of the method. This member **MAY** be omitted if the method expects no parameters. AOS methods typically use an `object` for `params`.
- `id`: An identifier established by the Client that **MUST** contain a String or Number(Integer) value. The Guardian Agent **MUST** reply with the same value in the Response object. This member is used to correlate the context between the two request and response objects.

#### 3.12.2. `JSONRPCResponse` Object

Responses from the Guardian Agent are encapsulated in a JSON-RPC Response object.

- `jsonrpc`: A String specifying the version of the JSON-RPC protocol. **MUST** be exactly `"2.0"`.
- `id`: This member is **REQUIRED**. It **MUST** be the same as the value of the `id` member in the Request Object. If there was an error in detecting the `id` in the Request object (e.g. Parse error/Invalid Request), it **MUST** be `null`.
- **EITHER** `result`: This member is **REQUIRED** on success. This member **MUST NOT** exist if there was an error invoking the method. The value of this member is determined by the method invoked on the Guardian Agent.
- **OR** `error`: This member is **REQUIRED** on failure. This member **MUST NOT** exist if there was no error triggered during invocation. The value of this member **MUST** be an [`JSONRPCError`](#313-jsonrpcerror-object) object.
- The members `result` and `error` are mutually exclusive: one **MUST** be present, and the other **MUST NOT**.

### 3.13. `JSONRPCError` Object

When a JSON-RPC call encounters an error, the Response Object will contain an `error` member with a value of this structure.


| Field Name | Type      | Required | Description                                                                                                  |
| :--------- | :-------- | :------- | :----------------------------------------------------------------------------------------------------------- |
| `code`     | `integer` | Yes      | Integer error code. See [Section 6 (Error Handling)](#6-error-handling) for error codes. |
| `message`  | `string`  | Yes      | Short, human-readable summary of the error.                                                                  |
| `data`     | `any`     | No       | Optional additional structured information about the error.                                                  |


### 3.14. `KnowledgeRetrievalStepParams` Object
Holds the parameters for the knowledge retrieval step. See `steps/knowledgeRetrieval` for more info.

| Field Name | Type      | Required | Description                                                                                                  |
| :--------- | :-------- | :------- | :----------------------------------------------------------------------------------------------------------- |
| `query`     | `string` | No      | The query extracted from agent's input and used to fetch data / knowledge. |
| `keywords`  | `string[]`  | No      | Keywords used to fetch data / knowledge. Usually used with word matching search.                                                                  |
| `results`     | [`KnowledgeRetrievalResult`](#3141-knowledgeretrievalresult-object)[]     | Yes       | Array of retrieved knowledge.                                                  |


#### 3.14.1. `KnowledgeRetrievalResult` Object
Represents a result of knowledge retrieval process.

| Field Name | Type      | Required | Description                                                                                                  |
| :--------- | :-------- | :------- | :----------------------------------------------------------------------------------------------------------- |
| `id`     | `string` | Yes      | The Id of the source. The Id is identical to the `Resource` id in the list of agent's available resources (`resources`) if found. |
| `content`  | `string`  | Yes      | The retrieved content from the source.                                                                  |
| `mimeType`                              | `string`                                                            | No      | [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) (e.g., text/plain, image/png). Strongly recommended.                                                                                                           | 
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the retrieved result. |


### 3.15. `ToolCallRequest` Object
Information about the tool call request.<br>
Agents use tools to complete tasks and fulfill user's requests. Available tools might be listed in [`Agent`](#31-agent-object) object under `tools`.<br>
Using descriptions from [`ToolDefinition`](#32-tooldefinition-object), the agent decide on which tool to call and on arguments to provide.<br>

| Field Name | Type      | Required | Description                                                                                                  |
| :--------- | :-------- | :------- | :----------------------------------------------------------------------------------------------------------- |
| `executionId`     | `string` | Yes      | Execution id of the tool provided by the orchestrator/planner. This id is used later on by the agent and LLM to correlate between tool call request and result. |
| `toolId`  | `string`  | Yes      | The Id of the tool as specified in [`ToolDefinition`](#32-tooldefinition-object) if exists in `Agent`'s tools.                                                                   |
| `inputs`     | [`ToolArgumentValue`](#3151-toolargumentvalue-object)[]     | Yes       | Array of inputs for the tool.                                                  |


#### 3.15.1. `ToolArgumentValue` Object
Defines a single argument / input for the tool.

| Field Name | Type      | Required | Description                                                                                                  |
| :--------- | :-------- | :------- | :----------------------------------------------------------------------------------------------------------- |
| `name`     | `string` | Yes      | The name of the argument. This is correlated with argument's name as specified in [`ToolArgumentDefinition`](#321-toolargumentdefinition-object) |
| `id`  | `string`  | No      | The id of the argument. It is correlated with argument's id as specified in [`ToolArgumentDefinition`](#321-toolargumentdefinition-object)                                                                   |
| `value`                              | `string`\| `number` \| `boolean` \| `object` \| `array` \| `null`                                                           | Yes      | The argument's value.                                                                                                           |


## 4. Protocol RPC Methods
All AOS RPC methods are invoked by the agent by sending an HTTP POST request to the guardian agent. The body of the HTTP POST request **MUST** be a `JSONRPCRequest` object, and the `Content-Type` header **MUST** be `application/json`.

The guardian's agent HTTP response body **MUST** be a `JSONRPCResponse` object. The `Content-Type` for JSON-RPC responses is `application/json`.<br>

Most of the protocol methods refer to steps within the agent's workflow: tool call, knowledge, memory etc.<br>
AOS also supports industial standards for Agent to Agent communication (A2A protocol) and tool call and context (MCP protocol).

### 4.1. steps/agentTrigger
This is the first step that activates or triggers the agent as a result or a response to an event.<br>
This method should be used after the agent's input is extracted from the trigger and before it gets to the agent.


#### 4.1.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `context`       | [`StepContext`](#38-stepcontext-object)                                 | Yes      | The context of the current step. |
| `trigger` | [`AgentTrigger`](#36-agenttrigger-object) | Yes       | The trigger that activated the agent.                        |


#### 4.1.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.1.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).


### 4.2. steps/knowledgeRetrieval
This step refers to the process of fetching relevant information from an external source (like document store, vector databse, API etc.) to ground agent's response in facts, context and data.<br>
Result can be a chunk or multiple chunks of data from a source.<br>
There are many retrieval techniques including semantic search (embedding-based similarity) and keyword search (exact/partial matching), or any combination.


#### 4.2.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `context`       | [`StepContext`](#38-stepcontext-object)                                 | Yes      | The context of the current step. |
| `knowledgeStep` | [`KnowledgeRetrievalStepParams`](#314-knowledgeretrievalstepparams-object) | Yes       | Knowledge retrieval step parameters.                        |
| `reasoning`       | `string`                               | No      | Agent's reasoning. |


#### 4.2.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.2.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).

### 4.3. steps/memoryStore
This step refers to the process of memorizing and store memory to the memory store for additional context for future or current agent interactions.<br>
Mostly, interaction history or a summary is stored to the memory store.

#### 4.3.1. **Request `params` Object**

| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `context`       | [`StepContext`](#38-stepcontext-object)                                 | Yes      | The context of the current step. |
| `memory` | `string`[]| Yes       | Array of retrieved memory contents. For JSON structured memory (for example chat history), a stringified JSON should be provided.                       |
| `reasoning`       | `string`                               | No      | Agent's reasoning. |


#### 4.3.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.3.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).


### 4.4. steps/memoryContextRetrieval
This step refers to the process of retrieving memory to add to the context of the current agent interactions.<br>
This context is passed alongside with the agent's instructions(system prompt), user prompt and additional information such as retrieved knowledge to the LLM.

#### 4.4.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `context`       | [`StepContext`](#38-stepcontext-object)                                 | Yes      | The context of the current step. |
| `memory` | `string`[]| Yes       | Array of retrieved memory contents. For JSON structured memory (for example chat history), a stringified JSON should be provided.                       |
| `reasoning`       | `string`                               | No      | Agent's reasoning. |


#### 4.4.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.4.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).


### 4.5. steps/message
Message step refers to the agent's input or output - depends on the `role`.<br>
A message with `user` role represents the user prompt / agent's input from the user. The method with `user` message **must** be used before the extracted input gets into the agent.<br>
A message with `agent` role represents the agent's output (AI response).The method with `agent` message **must** be used after the agent's response is ready and before it is sent back to the user.<br>
A message with `system` role represents a message from the system, such as guardrails controls etc. The method with `system` message **must** be used a before it is sent back to the user.

#### 4.5.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `context`       | [`StepContext`](#38-stepcontext-object)                                 | Yes      | The context of the current step. |
| `message` |[`Message`](#33-message-object)| Yes       | The message.                       |
| `citation` | [`Source`](#37-source-union-type)[]| Yes       | Array of referenced sources. Relevant mostly with `agent` message.                       |
| `reasoning`       | `string`                               | No      | Agent's reasoning. Should be used with `agent` or `system` message. |


#### 4.5.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.5.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).


### 4.6. steps/toolCallRequest
Agents use tools to complete tasks and fulfill user's requests.<br>
This method should be used after tool inputs are inferred by the LLM and before calling the tool.

#### 4.6.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `context`       | [`StepContext`](#38-stepcontext-object)                                 | Yes      | The context of the current step. |
| `toolCallRequest` |[`ToolCallRequest`](#315-toolcallrequest-object)| Yes       | Tool call request details.                       |
| `reasoning`       | `string`                               | No      | Agent's reasoning. |



#### 4.5.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.5.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).

### 4.6. steps/toolCallResult
This method should be used after tool is completed and before the result goes back into the LLM for further processing.

#### 4.6.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `context`       | [`StepContext`](#38-stepcontext-object)                                 | Yes      | The context of the current step. |
| `executionId` |`string`| Yes       | Execution id, correlated with executionId in [`ToolCallRequest`](#315-toolcallrequest-object) that was previously provided in `steps/toolCallRequest`.                       |
| `result` |[`ToolCallResult`](#4611-toolcallresult-object)| Yes       | Result.                       |


##### 4.6.1.1. `ToolCallResult` Object
| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `outputs`       | [`TextPart`](#341-textpart-object)[]                                 | Yes      | Array of `TextPart`. Can be empty if tool does not have output. |
| `isError` |`boolean`| Yes       | Whether tool completed successfully or resulted in an error.                       |


#### 4.6.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.6.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).


### 4.7. protocols/A2A
This method should be used to wrap all [A2A](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/) communications and messages.<br>
This method should be used before sending A2A message to a remote agent to monitor outbound communications.<br>
This method should be used after receiving A2A message (response) from a remote agent to monitor inbound communications.<br>
Read more about A2A support in [extend_a2a](../instrument/extend_a2a.md).


#### 4.7.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `message`       | `object`                               | Yes      | A2A-compliant message. |
| `reasoning`       | `string`                               | No      | Agent's reasoning. |

#### 4.7.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.7.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).

### 4.8. protocols/MCP
This method should be used to wrap all [MCP](https://modelcontextprotocol.io/introduction) communications and messages.<br>
This method should be used before sending MCP message to MCP server to monitor outbound communications.<br>
This method should be used after receiving MCP message (response) from a MCP server to monitor inbound communications.<br>
Read more about MCP support in [extend_mcp](../instrument/extend_mcp.md).


#### 4.8.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `message`       | `object`                               | Yes      | MCP-compliant message. |
| `reasoning`       | `string`                               | No      | Agent's reasoning. |

#### 4.8.2. **Response on success**: [`AOSSuccessResponse`](#51-aossuccessresponse-object).
#### 4.8.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).

### 4.9. ping
This method is used by the agent to ensure that guardian agent is alive.


#### 4.9.1. **Request `params` Object**


| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `timestamp`                   | `string` (ISO 8601) | Yes       | Timestamp (UTC recommended). |
| `timeout`                   | `integer`| No       | Timeout in milliseconds after which the communication with guardian agent is considered to be lost. |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the agent. |

#### 4.9.2. **Response on success**: [`PingRequestSuccessResponse`](#53-pingrequestsuccessresponse-object).
#### 4.9.3. **Response on failure**: [`JSONRPCErrorResponse`](#52-jsonrpcerrorresonse-object).

## 5. Responses

### 5.1. `AOSSuccessResponse` Object
| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `id`                   | `string` \| `integer`  | Yes       | Same id as the id in the correlated request. |
| `jsonrpc`                   |`"2.0"` (literal)| Yes       | JSON-RPC version string. |
| `result`                   |[`AOSSuccessResult`](#511-aossuccessresult-object)| Yes       | Success result. |

#### 5.1.1. `AOSSuccessResult` Object

| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `decision`                   | `string`  | Yes       | Guardian agent's de. One of `allow`, `deny`, `modify`. |
| `reasoning`                   | `string`| No       | Guardian agent's reasoning/thought explaining the decision. |
| `reasonCode`                   | `string`[] | No       | Timestamp (UTC recommended). |
| `message`                   | `string`| Yes       | Human readable message explaining the decision. |
| `data`                   | `Record<string, any>` | No       | Additional key-value data. |
| `modifiedRequest`                   | `AOSRequest` | No       | Modified request. This is relevant when decision is `modify`. |

### 5.2.`JSONRPCErrorResponse` Object
| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `id`                   | `string`  | Yes       | Response id. This should be the same as the request id. |
| `error`                   | `string`| Yes       | One of `JSONRPCError`, `JSONParseError`, `InvalidRequestError`, `MethodNotFoundError`, `InvalidParamsError`, `InternalError`. |
| `jsonrpc`                   |`"2.0"` (literal)| Yes       | JSON-RPC version string. |



### 5.3. `PingRequestSuccessResponse` Object
| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `id`                   | `string` \| `integer`  | Yes       | Same id as the id in the correlated ping request. |
| `result`                   |[`PingRequestResult`](#531-pingrequestresult-object)| Yes       | Ping result. |
| `jsonrpc`                   |`"2.0"` (literal)| Yes       | JSON-RPC version string. |


#### 5.3.1. `PingRequestResult` Object

| Field Name      | Type                                                            | Required | Description                                                        |
| :-------------- | :-------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| `status`                   | `string`  | Yes       | Guardian agent's status. One of `connected`, `error`. |
| `version`                   | `string`| Yes       | Guardian agent's version. |
| `timestamp`                   | `string` (ISO 8601) | Yes       | Timestamp (UTC recommended). |
| `metadata`                   | `Record<string, any>` | No       | Arbitrary key-value metadata associated with the agent. |

## 6. Error Handling

AOS uses standard [JSON-RPC 2.0 error codes and structure](https://www.jsonrpc.org/specification#error_object) for reporting errors. Errors are returned in the `error` member of the `JSONRPCErrorResponse` object. See [`JSONRPCError` Object definition](#313-jsonrpcerror-object).

### 6.1. Standard JSON-RPC Errors

These are standard codes defined by the JSON-RPC 2.0 specification.

| Code                 | JSON-RPC Spec Meaning | Typical AOS `message`     | Description                                                                                  |
| :------------------- | :-------------------- | :------------------------ | :------------------------------------------------------------------------------------------- |
| `-32700`             | Parse error (JSONParseError)          | Invalid JSON payload      | Server received JSON that was not well-formed.                                               |
| `-32600`             | Invalid Request (InvalidRequestError)      | Invalid JSON-RPC Request  | The JSON payload was valid JSON, but not a valid JSON-RPC Request object.                    |
| `-32601`             | Method not found (MethodNotFoundError)      | Method not found          | The requested AOS RPC `method` (e.g., `"steps/foo"`) does not exist or is not supported.     |
| `-32602`             | Invalid params (InvalidParamsError)        | Invalid method parameters | The `params` provided for the method are invalid (e.g., wrong type, missing required field). |
| `-32603`             | Internal error (InternalError)       | Internal server error     | An unexpected error occurred on the server during processing.                                |
| `-32000` to `-32099` | Server error          | _(Server-defined)_        | Reserved for implementation-defined server-errors. AOS-specific errors use this range.       |
