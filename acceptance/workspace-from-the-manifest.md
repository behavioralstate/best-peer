# An agent drives a workspace on a GPU host from the manifest alone

The acceptance run of [behavioralstate/spec#62](https://github.com/behavioralstate/spec/issues/62), which also proves
[behavioralstate/spec#73](https://github.com/behavioralstate/spec/issues/73): an LLM client connected through the
published connector signs in to a door, creates a workspace, configures a cloud with a GPU machine in it, deploys a
model there, sends it the `prompt` command and reads `PromptAnswered`, runs a job and undeploys, with nothing written
for it beyond the manifest. This file is the record of the run that passed: how it was set up, what it showed, and the
transcript. The run before workspaces and the `prompt` command is
[lifecycle-from-the-manifest.md](lifecycle-from-the-manifest.md).

## The run

- **The machine**: a VM rented on Verda on 2026-10-22, one Tesla V100-SXM2-16GB, NVIDIA driver 580.178.04 (CUDA
  13.0), Docker 29.9.1 with the NVIDIA runtime, Ubuntu 24.04 on Verda's own V100 image.
- **The peers**: best-peer 0.0.22 from the release, installed with `install.sh`, two processes on that VM, each on a
  fresh data folder and on loopback `http://`. The GPU member, `BEST_PEER_RUNTIME=docker` (the default) and the
  NVIDIA adapter, on port 7777. The door the agent entered by, `BEST_PEER_GPU=none BEST_PEER_RUNTIME=fake`, on port
  7778: it runs nothing of its own, so everything that ran, ran on the member through the cloud. The client reached
  the door through an SSH tunnel, so the door's address was `http://127.0.0.1:7778` on both ends.
- **The client**: GitHub Copilot CLI 1.0.101, interactive (`copilot -i` with the person's sentence), on Claude Sonnet
  5.5, which its Auto setting chose. The one MCP server added for the run was the published connector,
  `@behavioralstate/best-mcp` 2.6.0, with no connection configured, `BEST_MCP_ALLOW_LOCAL=true` because the door was
  on loopback, and its credential file in a scratch folder deleted afterwards. The client's built-in GitHub servers
  were disabled; the owner's connectors to other services stayed loaded and none was called. Every call in the
  transcript is to a `best-*` tool of the connector, the client's own tool search, or its `ask_user`, the two
  questions it put to the person.
- **Nothing written for the agent**: the person's sentence at the top of the transcript is all it got. It read both
  catalogues at the root and in the workspace, and five schema documents, and never saw this repository.
- **The person's part**: two approvals at the machine and two answers to the client. The agent's code, `7V8R-2ZF8`,
  was approved at the door with `best-peer approve` at 12:44:01, six seconds after the client showed it; the client
  waited for the person's answer until 12:46:08. The cloud's sign-in to the member, whose code the door logged at
  12:46:25 (`to admit cloud lab of workspace ws-a8efdd1655d9 on gpu, run on that machine: best-peer approve
  5M9L-83J2`), was approved at the member in the same second, and the door logged the member's admission at 12:46:30,
  on its next poll. Both approvals were made over SSH from the owner's session: the agent's six seconds after the
  client showed its code, the member's before the client asked for it; the person answered the client's two questions ("approved?") in its terminal.
- **The validator**: the door, through the same tunnel, passed `best-validate` 0.4.2 (BEST 0.9.17, conformant, 0
  failures, 0 warnings) anonymous after the run.

## What the run showed

- Every step completed and nothing was refused: sign-in; `create-workspace` at the root; the workspace reached as
  the connector's connection `run62/ws-a8efdd1655d9` with the credential that made it (spec#73); `configure-cloud`;
  the hardware state with the V100 as `lab/gpu/GPU-eeeeb51b-…` and the host CPU; the deploy; the `prompt` command and
  `PromptAnswered`; a job run to `JobFinished`; the undeploy. Afterwards `docker ps -a` on the member listed no
  container.
- Every fact on the workspace's stream from `CloudConfiguredV1` on named the cloud, and every one a member told
  named the peer too:
  `PeerJoined`, the image pull, the deployment's start, load and readiness, the prompt's answer, the job's placement,
  start and end, the undeploy. The job's order, `JobQueued`, names the cloud alone, since no peer holds it yet.
- The prompt was a command on the door like any other: `PromptAnswered` came back on the workspace's stream under
  the prompt's correlation id with the answer, `Hello, how are you today?` (8 completion tokens, 34 prompt tokens,
  finish `stop`), and the client never reached the engine's port, which stayed on the member's loopback.
- The job's end carried what it printed: `JobFinished` with exit code 0 and `output` `GPU 0: Tesla V100-SXM2-16GB
  (UUID: GPU-eeeeb51b-5115-3cf8-088f-8b95bc937762)`, the line the earlier run could not show
  ([behavioralstate/spec#39](https://github.com/behavioralstate/spec/issues/39)). The cloud took the job as the order
  `job-cb78d686d58e` (`JobQueued`, `JobPlaced`); the member ran it as `job-863bbb657c6f`, and its `JobStarted`,
  relayed, names the order.
- The agent read the hardware state at 12:46:29, half a second before the door's poll picked up the member's
  admission: no device, and the peer `joining`. From the schema documents alone it told the person that the door
  logs a code to approve on that machine and asked them to approve it, which had been done at 12:46:25; its next read,
  after their answer, had the V100.
- The deploy pulled the engine image, `ollama/ollama:0.40.6`, in 1 minute 16 seconds, and the model was ready 13
  seconds after that. The workspace's log has 30 progress events for the whole run (`ImagePulling` 20,
  `WeightsLoading` 10), where the earlier run's had 326
  ([behavioralstate/spec#40](https://github.com/behavioralstate/spec/issues/40)). The pull's first two read 1 % then
  0 %, as Docker found more layers to fetch.
- The agent followed the deploy on the stream, `sample_event_stream` filtered by the command's correlation id and
  then by `DeploymentReady`, read the prompt's answer with `get_events`, and waited for the job's `JobFinished` on the
  stream.
- 31 tool calls in the transcript, the client's two questions to the person among them; 25 model turns. From the
  client's own log, 6 minutes 2 seconds from the person's sentence to the agent's last answer, 2 minutes 37 seconds
  of them waiting for the person (6 minutes 20 seconds from the client's start).

## The transcript

Rendered from the client's own session log: every message in order, tool calls numbered with their arguments, each
result under its call (shortened where it ran past a screen, event lists as one line per event), and the client's two
questions to the person with their answers. The credential appears only as the connector's redaction; the owner's
other connectors are named as such.

---

**The person:**

> Sign me in as run62, starting from http://127.0.0.1:7778/.well-known/best. Then create a workspace called research, and configure a cloud called lab in it with the peer gpu=http://127.0.0.1:7777. Show me the hardware the workspace sees. Deploy qwen2.5:0.5b on lab and follow it until it is ready, prompt it with "Say hello in five words" and show me the answer, run a job on lab with the image nvidia/cuda:12.4.0-base-ubuntu22.04 running nvidia-smi -L and show me its output, then undeploy the model.

1. `tool_search_tool` {"pattern": "best|<another connector>", "limit": 30}

   ```
   Found 30 matching tool(s), 15 of them the owner's other connectors (not called): best-exchange_device_code, best-execute_query, best-get_command_catalogue, best-get_command_schema, best-get_event_schema, best-get_events, best-get_manifest, best-get_query_catalogue, best-get_query_schema, best-get_workflows, best-list_connections, best-register_agent, best-sample_event_stream, best-send_command, best-send_command_and_wait
   ```

2. `best-register_agent` {"name": "run62", "manifest": "http://127.0.0.1:7778/.well-known/best", "agent_label": "GitHub Copilot CLI"}

   ```
   {
    "name": "run62",
    "resolved": "http://127.0.0.1:7778/.well-known/best",
    "user_code": "7V8R-2ZF8",
    "verification_uri": "http://127.0.0.1:7778/auth/verify",
    "verification_uri_complete": "http://127.0.0.1:7778/auth/verify?user_code=7V8R-2ZF8",
    "expires_in": 600,
    "interval": 5,
    "next": "SHOW THE PERSON THE LINK AND THE CODE NOW, exactly as returned (verification_uri_complete already carries the code), and ask them to open it in their own browser: there they sign in — or sign up, where the service offers it — and approve you. Never open it yourself or in a browser you control: approving is theirs. Then call exchange_device_code with connection 'run62' and no device_code; …
   }
   ```

3. The agent asks the person: Please open this link and approve the sign-in as run62: http://127.0.0.1:7778/auth/verify?user_code=7V8R-2ZF8 (code: 7V8R-2ZF8). Tell me when done.

   **The person:** {"done": true}

4. `best-exchange_device_code` {"connection": "run62"}

   ```
   {
    "access_token": "<stored by best-mcp — never shown to the model>",
    "auth_header": "X-Api-Key",
    "endpoint": "http://127.0.0.1:7778",
    "manifest": "http://127.0.0.1:7778/.well-known/best",
    "name": "run62",
    "ready_check": "http://127.0.0.1:7778/queries",
    "token_type": "apikey",
    "session": {
     "connection": "run62",
     "connections": [
      {
       "name": "run62",
       "endpoint": "http://127.0.0.1:7778"
      }
     ],
     "signed_in_at": "http://127.0.0.1:7778/.well-known/best",
     "stored_under": "run62",
     "stored_at": "<a scratch folder of this machine>/credentials.json",
     "note": "Signed in under 'run62'. Pass connection 'run62' on every call for this service — it works now and at every later start. The key itself was not returned and must never be typed into the conversation."
    }
   }
   ```

5. `best-get_command_catalogue` {"connection": "run62"}

   ```
   [
    {
     "commandType": "PullImage",
     "dataschema": "http://127.0.0.1:7778/commands/pull-image/1.0",
     "description": "Pulls a container image from its registry onto this peer, whether or not the peer holds it already, so a later deploy or job can start at once: how a held image is refreshed where a deploy or a job…",
     "schema": "pull-image",
     "version": "1.0"
    },
    {
     "commandType": "DeployModel",
     "dataschema": "http://127.0.0.1:7778/commands/deploy-model/1.0",
     "description": "Serves a model on this peer with the engine named, on a device that offers an API the engine runs on and has the memory asked for free. Refused at once, with the reason and what to do, when no device…",
     "schema": "deploy-model",
     "version": "1.0"
    },
    {
     "commandType": "UndeployModel",
     "dataschema": "http://127.0.0.1:7778/commands/undeploy-model/1.0",
     "description": "Stops a deployment and frees its device memory. Refused when no such deployment is live, or when another credential deployed it. The outcome is an Undeployed event with this command's correlation id.…",
     "schema": "undeploy-model",
     "version": "1.0"
    },
    {
     "commandType": "RunJob",
     "dataschema": "http://127.0.0.1:7778/commands/run-job/1.0",
     "description": "Runs an image once, with the arguments given, and tells its end. With memory_bytes the job is placed on a device with that much room and handed that device; without, it runs with no device. With…",
     "schema": "run-job",
     "version": "1.0"
    },
    {
     "commandType": "StopJob",
     "dataschema": "http://127.0.0.1:7778/commands/stop-job/1.0",
     "description": "Stops a running job, or an order that waits or is not yet started, named by the id JobQueued gave it, which ends before it started: JobStopped under the order's own correlation id too (on a peer's…",
     "schema": "stop-job",
     "version": "1.0"
    },
    {
     "commandType": "Prompt",
     "dataschema": "http://127.0.0.1:7778/commands/prompt/1.0",
     "description": "Asks a ready deployment on this peer to answer a conversation, whole. The messages are the conversation so far, each with its role (system, user, assistant) and content; max_tokens, temperature and…",
   … (46 more lines)
   ```

6. `best-get_query_catalogue` {"connection": "run62"}

   ```
   [
    {
     "dataschema": "http://127.0.0.1:7778/queries/get-hardware-state/1.0",
     "description": "The accelerators on this host right now: each device's compute APIs with their versions, its memory total and free, temperature, power and utilisation, the isolation a workload on it gets, and the…",
     "schema": "get-hardware-state",
     "version": "1.0"
    },
    {
     "dataschema": "http://127.0.0.1:7778/queries/get-workloads/1.0",
     "description": "What this peer runs for you now: each deployment with its model, engine, device, the memory promised to it, its phase (starting, ready, ending); each job with its image, device and phase (running,…",
     "schema": "get-workloads",
     "version": "1.0"
    },
    {
     "dataschema": "http://127.0.0.1:7778/queries/get-workspaces/1.0",
     "description": "Who you are on this door and where you belong: identity, the opaque id of your credential, which an owner names to invite you; workspaces, every workspace you own or are a member of, each with its…",
     "schema": "get-workspaces",
     "version": "1.0"
    }
   ]
   ```

7. `best-get_workflows` {"connection": "run62"}

   ```
   This endpoint publishes no workflows.
   ```

8. `best-get_command_schema` {"connection": "run62", "schema": "create-workspace", "version": "1.0"}

   ```
   {
    "$id": "http://127.0.0.1:7778/commands/create-workspace/1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "commandType": "CreateWorkspace",
    "completes": [
     "WorkspaceCreatedV1"
    ],
    "description": "Makes a workspace, the organization or team that holds clouds and admits the identities who may use them, with you as its owner. The outcome is a WorkspaceCreatedV1 event with this command's correlation id, naming the new workspace's id; get-workspaces then lists it with the endpoint of its own door, where configure-cloud makes its first cloud. Any credential may create a workspac …
    "produces": [
     "WorkspaceCreatedV1",
     "CommandFailed"
    ],
    "properties": {
     "name": {
      "description": "What the workspace is called, for people; the id is the door's",
      "maxLength": 100,
      "minLength": 1,
      "type": "string"
     }
    },
    "required": [
     "name"
    ],
    "title": "CreateWorkspace",
    "type": "object"
   }
   ```

9. `best-send_command_and_wait` {"connection": "run62", "schema": "create-workspace", "version": "1.0", "data": {"name": "research"}, "poll_query": "get-workspaces", "poll_until_contains": "research"}

   ```
   Command accepted. ID: 7d1aeaa9-7850-4485-8260-4fd5c87d3851
   Correlation ID: 7d1aeaa9-7850-4485-8260-4fd5c87d3851 — pass it as get_events / sample_event_stream params {"correlationId": "7d1aeaa9-7850-4485-8260-4fd5c87d3851"} to observe the outcome events.
   
   Query result after processing:
   {
     "identity": "84b1fbc15d1c1c03",
     "invitations": [],
     "workspaces": [
       {
         "endpoint": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9",
         "manifest": "http://127.0.0.1:7778/.well-known/best/ws-a8efdd1655d9",
         "members": [
           {
             "identity": "84b1fbc15d1c1c03",
             "role": "owner"
           }
         ],
         "name": "research",
         "role": "owner",
         "workspace": "ws-a8efdd1655d9"
       }
     ]
   }
   ```

**The agent:** The workspace has its own door. Let me see its connection and catalogue.

10. `best-get_command_catalogue` {"connection": "run62/ws-a8efdd1655d9"}

   ```
   [
    {
     "commandType": "PullImage",
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/pull-image/1.0",
     "description": "Pulls a container image from its registry onto every peer of the cloud named, whether or not a peer holds it already, so a later deploy or job there can start at once: how a held image is refreshed…",
     "schema": "pull-image",
     "version": "1.0"
    },
    {
     "commandType": "DeployModel",
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/deploy-model/1.0",
     "description": "Serves a model in a cloud of this workspace with the engine named, on the member peer whose device offers an API the engine runs on and has the memory asked for free; name the cloud, or a device…",
     "schema": "deploy-model",
     "version": "1.0"
    },
    {
     "commandType": "UndeployModel",
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/undeploy-model/1.0",
     "description": "Stops a deployment and frees its device memory. Refused when no such deployment is live, or when another credential deployed it. The outcome is an Undeployed event with this command's correlation id.…",
     "schema": "undeploy-model",
     "version": "1.0"
    },
    {
     "commandType": "RunJob",
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/run-job/1.0",
     "description": "Orders an image run once in a cloud of this workspace, with the arguments given, and tells its end. With memory_bytes the job is placed on a member peer's device with that much room and handed that…",
     "schema": "run-job",
     "version": "1.0"
    },
    {
     "commandType": "StopJob",
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/stop-job/1.0",
     "description": "Stops a running job, or an order that waits or is not yet started, named by the id JobQueued gave it, which ends before it started: JobStopped under the order's own correlation id too (on a peer's…",
     "schema": "stop-job",
     "version": "1.0"
    },
    {
     "commandType": "Prompt",
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/prompt/1.0",
     "description": "Asks a ready deployment in a cloud of this workspace to answer a conversation, whole; the deployment names its cloud and peer. The messages are the conversation so far, each with its role (system,…",
   … (46 more lines)
   ```

11. `best-get_query_catalogue` {"connection": "run62/ws-a8efdd1655d9"}

   ```
   [
    {
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/queries/get-hardware-state/1.0",
     "description": "The accelerators of this workspace's clouds right now: every device of every peer that answers in a cloud that is not archived, named cloud/peer/device, with the cloud and the peer on each, its…",
     "schema": "get-hardware-state",
     "version": "1.0"
    },
    {
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/queries/get-workloads/1.0",
     "description": "What this workspace runs for you now, across its clouds: each deployment with its cloud, the peer it is on, its model, engine, device (cloud/peer/device), the memory promised to it, its phase…",
     "schema": "get-workloads",
     "version": "1.0"
    },
    {
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/queries/get-clouds/1.0",
     "description": "The clouds of this workspace: each named pool of machines with its member peers (name and endpoint) and whether each answers (up), has not admitted the cloud yet (joining) or does not answer…",
     "schema": "get-clouds",
     "version": "1.0"
    },
    {
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/queries/get-menu/1.0",
     "description": "What each cloud of this workspace sells by: its sizes, each a name, its floors (the device memory it needs, the compute API at the least version, the host memory of the device's machine), the share…",
     "schema": "get-menu",
     "version": "1.0"
    },
    {
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/queries/get-usage/1.0",
     "description": "What the orders by size of this workspace used and what they cost, read from its own events: each job from its JobStarted, whose receipt carries the price per second, to its JobFinished, JobFailed or…",
     "schema": "get-usage",
     "version": "1.0"
    },
    {
     "dataschema": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/queries/get-store/1.0",
     "description": "This workspace's store, where its jobs' inputs come from and their outputs go: its endpoint, bucket and region, or null when its owner has set none (set-store). The credential is never shown.",
     "schema": "get-store",
     "version": "1.0"
    }
   ]
   ```

12. `best-get_command_schema` {"connection": "run62/ws-a8efdd1655d9", "schema": "configure-cloud", "version": "1.0"}

   ```
   {
    "$id": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/configure-cloud/1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "commandType": "ConfigureCloud",
    "completes": [
     "CloudConfiguredV1"
    ],
    "description": "Makes a cloud of this workspace, a named pool of machines, or changes the members of one that exists; an archived cloud of that name comes back. Each member is a peer by name and the base URL of its door; its devices appear as cloud/peer/device once its owner admits this cloud: the door's log shows the code to approve on that machine (best-peer approve <code>), and get-clouds show …
    "produces": [
     "CloudConfiguredV1",
     "CommandFailed"
    ],
    "properties": {
     "cloud": {
      "description": "The cloud's name, one word: what deploy-model names and the first part of its device ids",
      "maxLength": 64,
      "minLength": 1,
      "type": "string"
     },
     "members": {
      "description": "The machines in the cloud: each a peer's name, one word, and the base URL of its door",
      "items": {
       "additionalProperties": false,
       "properties": {
        "endpoint": {
         "description": "The base URL of the peer's door, as its manifest advertises it",
         "maxLength": 2048,
         "pattern": "^https?://",
         "type": "string"
        },
        "peer": {
         "description": "The name this cloud knows the machine by: the middle part of its device ids, and what every fact about a workload there carries as peer",
         "maxLength": 64,
         "minLength": 1,
         "type": "string"
        }
       },
       "required": [
        "peer",
   … (16 more lines)
   ```

13. `best-get_command_schema` {"connection": "run62/ws-a8efdd1655d9", "schema": "deploy-model", "version": "1.0"}

   ```
   {
    "$id": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/deploy-model/1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "commandType": "DeployModel",
    "completes": [
     "DeploymentEnded",
     "DeploymentFailed",
     "DeploymentReady",
     "OutOfMemory"
    ],
    "description": "Serves a model in a cloud of this workspace with the engine named, on the member peer whose device offers an API the engine runs on and has the memory asked for free; name the cloud, or a device (cloud/peer/device) to pin the placement, which names the cloud too. Refused at once, with the reason and what to do, when the cloud is not this workspace's, is archived, or no device in i …
    "produces": [
     "ImagePulling",
     "ImagePulled",
     "DeploymentStarted",
     "WeightsLoading",
     "DeploymentReady",
     "DeploymentFailed",
     "OutOfMemory",
     "DeploymentEnded"
    ],
    "properties": {
     "cloud": {
      "description": "The cloud of this workspace to place in; may be left out when device names it; get-clouds lists them",
      "maxLength": 64,
      "type": "string"
     },
     "device": {
      "description": "A device id from this workspace's get-hardware-state, cloud/peer/device, to pin the placement; otherwise the fitting device of the cloud with the most room",
      "maxLength": 256,
      "type": "string"
     },
     "engine": {
      "description": "ollama runs on cuda, rocm or cpu; vllm on cuda",
      "enum": [
       "ollama",
       "vllm"
      ],
      "type": "string"
   … (31 more lines)
   ```

14. `best-get_command_schema` {"connection": "run62/ws-a8efdd1655d9", "schema": "run-job", "version": "1.0"}

   ```
   {
    "$id": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/run-job/1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "commandType": "RunJob",
    "completes": [
     "JobFailed",
     "JobStarted",
     "JobStopped"
    ],
    "description": "Orders an image run once in a cloud of this workspace, with the arguments given, and tells its end. With memory_bytes the job is placed on a member peer's device with that much room and handed that device; without, it runs on the first peer of the cloud that answers, with no device. Name the cloud, or a device (cloud/peer/device) to pin the placement, which names the cloud too. Re …
    "produces": [
     "JobQueued",
     "JobPlaced",
     "ImagePulling",
     "ImagePulled",
     "InputsFetched",
     "JobStarted",
     "OutputsStored",
     "JobFinished",
     "JobFailed",
     "JobStopped"
    ],
    "properties": {
     "args": {
      "description": "The command line passed to the image's entrypoint",
      "items": {
       "maxLength": 4096,
       "type": "string"
      },
      "maxItems": 256,
      "type": "array"
     },
     "cloud": {
      "description": "The cloud of this workspace to run in; may be left out when device names it; get-clouds lists them",
      "maxLength": 64,
      "type": "string"
     },
     "deadline_seconds": {
      "description": "How long the job may run before it is stopped, counted from JobStarted; at most thirty days; without it the job runs to its end",
   … (94 more lines)
   ```

15. `best-get_command_schema` {"connection": "run62/ws-a8efdd1655d9", "schema": "prompt", "version": "1.0"}

   ```
   {
    "$id": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9/commands/prompt/1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "commandType": "Prompt",
    "completes": [
     "PromptAnswered",
     "PromptFailed"
    ],
    "description": "Asks a ready deployment in a cloud of this workspace to answer a conversation, whole; the deployment names its cloud and peer. The messages are the conversation so far, each with its role (system, user, assistant) and content; max_tokens, temperature and stop are the engine's knobs, and are left to the engine when not given. Refused at once, with the reason and what to do, when th …
    "produces": [
     "PromptAnswered",
     "PromptFailed"
    ],
    "properties": {
     "deployment": {
      "description": "The deployment to ask, as DeploymentReady and get-workloads name it; it must be ready",
      "maxLength": 128,
      "minLength": 1,
      "type": "string"
     },
     "max_tokens": {
      "description": "The most tokens the answer may have; the engine's default when not given",
      "maximum": 1048576,
      "minimum": 1,
      "type": "integer"
     },
     "messages": {
      "description": "The conversation so far, oldest first; the last is what the model answers",
      "items": {
       "additionalProperties": false,
       "properties": {
        "content": {
         "maxLength": 131072,
         "type": "string"
        },
        "role": {
         "enum": [
          "system",
          "user",
   … (39 more lines)
   ```

16. `best-send_command_and_wait` {"connection": "run62/ws-a8efdd1655d9", "data": {"cloud": "lab", "members": [{"peer": "gpu", "endpoint": "http://127.0.0.1:7777"}]}, "poll_query": "get-clouds", "poll_until_contains": "lab", "schema": "configure-cloud", "version": "1.0"}

   ```
   Command accepted. ID: bd82aec5-d7a4-4e68-a48e-5f006980786b
   Correlation ID: bd82aec5-d7a4-4e68-a48e-5f006980786b — pass it as get_events / sample_event_stream params {"correlationId": "bd82aec5-d7a4-4e68-a48e-5f006980786b"} to observe the outcome events.
   
   Query result after processing:
   {
     "clouds": [
       {
         "archived": false,
         "cloud": "lab",
         "peers": [
           {
             "endpoint": "http://127.0.0.1:7777",
             "peer": "gpu",
             "state": "joining"
           }
         ]
       }
     ]
   }
   ```

17. `best-execute_query` {"connection": "run62/ws-a8efdd1655d9", "schema": "get-hardware-state"}

   ```
   {
    "devices": [],
    "driver": null,
    "observed_at": "2026-10-22T12:46:29.872818052Z",
    "peers": [
     {
      "cloud": "lab",
      "endpoint": "http://127.0.0.1:7777",
      "peer": "gpu",
      "state": "joining"
     }
    ]
   }
   ```

18. `best-get_events` {"connection": "run62/ws-a8efdd1655d9"}

   ```
   12:46:15 WorkspaceCreatedV1 {"endpoint": "http://127.0.0.1:7778/workspaces/ws-a8efdd1655d9", "manifest": "http://127.0.0.1:7778/.well-known/best/ws-a8efdd1655d9", "name": "research", "owner": "84b1fbc15d1c1c03", "workspace": "ws-a8efdd1655d9"}
   12:46:25 CloudConfiguredV1 {"cloud": "lab", "members": [{"endpoint": "http://127.0.0.1:7777", "peer": "gpu"}], "workspace": "ws-a8efdd1655d9"}
   ```

**The agent:** The peer is still "joining": the machine owner must approve the cloud first.

19. The agent asks the person: The peer `gpu` (127.0.0.1:7777) shows as "joining", so no devices are visible yet. Its door's log shows a code to approve on that machine (`best-peer approve <code>`). Please approve it, then tell me to continue.

   **The person:** {"approved": true}

20. `best-execute_query` {"connection": "run62/ws-a8efdd1655d9", "schema": "get-hardware-state"}

   ```
   {
    "devices": [
     {
      "cloud": "lab",
      "compute": [
       {
        "api": "cuda",
        "version": "13.0"
       },
       {
        "api": "vulkan"
       }
      ],
      "id": "lab/gpu/GPU-eeeeb51b-5115-3cf8-088f-8b95bc937762",
      "isolation": "container",
      "memory": {
       "free_bytes": 16928342016,
       "total_bytes": 17179869184
      },
      "name": "Tesla V100-SXM2-16GB",
      "peer": "gpu",
      "power_w": 24.20800018310547,
      "slicing": "none",
      "temperature_c": 44,
      "utilisation_pct": 0,
      "vendor": "nvidia"
     },
     {
      "cloud": "lab",
      "compute": [
       {
        "api": "cpu"
       }
      ],
      "id": "lab/gpu/cpu-0",
      "isolation": "container",
      "memory": {
       "free_bytes": 23317348352,
       "total_bytes": 24142921728
      },
   … (27 more lines)
   ```

21. `best-send_command` {"connection": "run62/ws-a8efdd1655d9", "data": {"cloud": "lab", "model": "qwen2.5:0.5b", "engine": "ollama", "memory_bytes": 2147483648}, "schema": "deploy-model", "version": "1.0"}

   ```
   Command accepted. ID: e1385975-5613-4c97-bf58-3dfb1340497e
   Correlation ID: e1385975-5613-4c97-bf58-3dfb1340497e — pass it as get_events / sample_event_stream params {"correlationId": "e1385975-5613-4c97-bf58-3dfb1340497e"} to observe the outcome events.
   ```

22. `best-sample_event_stream` {"connection": "run62/ws-a8efdd1655d9", "max_events": 10, "max_seconds": 90, "params": {"correlationId": "e1385975-5613-4c97-bf58-3dfb1340497e"}}

   ```
   12:47:06 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 10}
   12:47:12 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 17}
   12:47:18 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 23}
   12:47:23 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 29}
   12:47:29 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 36}
   12:47:34 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 42}
   12:47:40 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 48}
   12:48:18 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 99}
   12:48:18 ImagePulling {"cloud": "lab", "image": "ollama/ollama:0.40.6", "peer": "gpu", "progress_pct": 100}
   12:48:18 ImagePulled {"cloud": "lab", "held": false, "image": "ollama/ollama:0.40.6", "peer": "gpu"}
   {"count": 10, "lastEventId": "07880c93-4b47-41c9-ab15-dcc9a2cddb62", "elapsedSeconds": 76.3, "endedBecause": "max_events reached", "note": "The stream is closed. Events arriving after this sample are not delivered — call again (passing lastEventId as last_event_id) to take another sample, or use get_events for history."}
   ```

23. `best-sample_event_stream` {"connection": "run62/ws-a8efdd1655d9", "last_event_id": "07880c93-4b47-41c9-ab15-dcc9a2cddb62", "max_events": 5, "max_seconds": 120, "params": {"correlationId": "e1385975-5613-4c97-bf58-3dfb1340497e"}}

   ```
   12:48:21 DeploymentStarted {"cloud": "lab", "container": "484dd9da9203d64eb6a9afdb127e729f825ab43c81c8eca868ab53937babce8a", "deployment": "dep-f2c9eb3ba48e", "device": "lab/gpu/GPU-eeeeb51b-5115-3cf8-088f-8b95bc937762", "engine": "ollama", "holder": "84b1fbc15d1c1c03", "memory_bytes": 2147483648, "model": "qwen2.5:0.5b", "peer": "gpu", "port": 32768}
   12:48:25 WeightsLoading {"cloud": "lab", "deployment": "dep-f2c9eb3ba48e", "model": "qwen2.5:0.5b", "peer": "gpu", "progress_pct": 0}
   12:48:25 WeightsLoading {"cloud": "lab", "deployment": "dep-f2c9eb3ba48e", "model": "qwen2.5:0.5b", "peer": "gpu", "progress_pct": 11}
   12:48:25 WeightsLoading {"cloud": "lab", "deployment": "dep-f2c9eb3ba48e", "model": "qwen2.5:0.5b", "peer": "gpu", "progress_pct": 23}
   12:48:26 WeightsLoading {"cloud": "lab", "deployment": "dep-f2c9eb3ba48e", "model": "qwen2.5:0.5b", "peer": "gpu", "progress_pct": 39}
   {"count": 5, "lastEventId": "3c129668-0819-49bb-807f-cbac0167ddd5", "elapsedSeconds": 4.4, "endedBecause": "max_events reached", "note": "The stream is closed. Events arriving after this sample are not delivered — call again (passing lastEventId as last_event_id) to take another sample, or use get_events for history."}
   ```

24. `best-sample_event_stream` {"connection": "run62/ws-a8efdd1655d9", "last_event_id": "3c129668-0819-49bb-807f-cbac0167ddd5", "max_events": 20, "max_seconds": 60, "params": {"correlationId": "e1385975-5613-4c97-bf58-3dfb1340497e", "type": "DeploymentReady"}}

   ```
   12:48:32 DeploymentReady {"cloud": "lab", "deployment": "dep-f2c9eb3ba48e", "engine": "ollama", "model": "qwen2.5:0.5b", "peer": "gpu"}
   {"count": 1, "lastEventId": "227ed3b4-7bd1-4543-82fa-6201bc94a559", "elapsedSeconds": 60, "endedBecause": "max_seconds reached", "note": "The stream is closed. Events arriving after this sample are not delivered — call again (passing lastEventId as last_event_id) to take another sample, or use get_events for history."}
   ```

**The agent:** Ready. Prompting now.

25. `best-send_command` {"connection": "run62/ws-a8efdd1655d9", "data": {"deployment": "dep-f2c9eb3ba48e", "messages": [{"role": "user", "content": "Say hello in five words"}]}, "schema": "prompt", "version": "1.0"}

   ```
   Command accepted. ID: c4361be2-a71a-49a4-8229-b2d11cde0e0b
   Correlation ID: c4361be2-a71a-49a4-8229-b2d11cde0e0b — pass it as get_events / sample_event_stream params {"correlationId": "c4361be2-a71a-49a4-8229-b2d11cde0e0b"} to observe the outcome events.
   ```

26. `best-get_events` {"connection": "run62/ws-a8efdd1655d9", "params": {"correlationId": "c4361be2-a71a-49a4-8229-b2d11cde0e0b"}}

   ```
   {
    "events": []
   }
   ```

27. `best-get_events` {"connection": "run62/ws-a8efdd1655d9", "params": {"correlationId": "c4361be2-a71a-49a4-8229-b2d11cde0e0b"}}

   ```
   12:49:33 PromptAnswered {"cloud": "lab", "completion_tokens": 8, "content": "Hello, how are you today?", "deployment": "dep-f2c9eb3ba48e", "finish": "stop", "model": "qwen2.5:0.5b", "peer": "gpu", "prompt_tokens": 34}
   ```

**The agent:** Now the job (GPU device, 1 GiB, with a deadline).

28. `best-send_command` {"connection": "run62/ws-a8efdd1655d9", "data": {"cloud": "lab", "image": "nvidia/cuda:12.4.0-base-ubuntu22.04", "args": ["nvidia-smi", "-L"], "memory_bytes": 1073741824, "deadline_seconds": 300}, "schema": "run-job", "version": "1.0"}

   ```
   Command accepted. ID: 08c886d7-89e5-4dec-9e18-22d16d227b16
   Correlation ID: 08c886d7-89e5-4dec-9e18-22d16d227b16 — pass it as get_events / sample_event_stream params {"correlationId": "08c886d7-89e5-4dec-9e18-22d16d227b16"} to observe the outcome events.
   ```

29. `best-sample_event_stream` {"connection": "run62/ws-a8efdd1655d9", "max_events": 1, "max_seconds": 120, "params": {"correlationId": "08c886d7-89e5-4dec-9e18-22d16d227b16", "type": "JobFinished"}}

   ```
   12:49:43 JobFinished {"cloud": "lab", "exit_code": 0, "job": "job-863bbb657c6f", "output": "GPU 0: Tesla V100-SXM2-16GB (UUID: GPU-eeeeb51b-5115-3cf8-088f-8b95bc937762)", "peer": "gpu"}
   {"count": 1, "lastEventId": "b59799e4-d878-4445-b7c9-68c02b8a9d82", "elapsedSeconds": 3.8, "endedBecause": "max_events reached", "note": "The stream is closed. Events arriving after this sample are not delivered — call again (passing lastEventId as last_event_id) to take another sample, or use get_events for history."}
   ```

30. `best-send_command` {"connection": "run62/ws-a8efdd1655d9", "data": {"deployment": "dep-f2c9eb3ba48e"}, "schema": "undeploy-model", "version": "1.0"}

   ```
   Command accepted. ID: 91995d49-2a7d-4a28-b51c-654172665859
   Correlation ID: 91995d49-2a7d-4a28-b51c-654172665859 — pass it as get_events / sample_event_stream params {"correlationId": "91995d49-2a7d-4a28-b51c-654172665859"} to observe the outcome events.
   ```

31. `best-get_events` {"connection": "run62/ws-a8efdd1655d9", "params": {"correlationId": "91995d49-2a7d-4a28-b51c-654172665859"}}

   ```
   12:49:45 Undeployed {"cloud": "lab", "deployment": "dep-f2c9eb3ba48e", "model": "qwen2.5:0.5b", "peer": "gpu"}
   ```

**The agent:** All steps are done:

- **Sign-in:** you're signed in as `run62`.
- **Workspace and cloud:** workspace `research` is `ws-a8efdd1655d9`. Cloud `lab` has the peer `gpu` at http://127.0.0.1:7777. The peer showed as "joining" until you approved it on that machine, then it went "up".
- **Hardware the workspace sees:**
  - Tesla V100-SXM2-16GB, about 16 GB free, CUDA 13.0 and Vulkan, container isolation. Its id is `lab/gpu/GPU-eeeeb51b-…`.
  - Intel Xeon Silver 4214R CPU, about 23 GB free.
  - Driver 580.178.04.
- **Deployment:** I deployed `qwen2.5:0.5b` with ollama on the GPU and reserved 2 GiB of device memory (that figure is my choice). I followed the events from image pull through weights loading to DeploymentReady as `dep-f2c9eb3ba48e`.
- **Prompt answer:** "Hello, how are you today?"
- **Job:** I ran `nvidia/cuda:12.4.0-base-ubuntu22.04` with `nvidia-smi -L`, reserving 1 GiB of device memory and a 300-second deadline (both my choices). It exited 0 with this output:
  `GPU 0: Tesla V100-SXM2-16GB (UUID: GPU-eeeeb51b-5115-3cf8-088f-8b95bc937762)`
- **Undeploy:** the deployment is stopped (Undeployed event received).
