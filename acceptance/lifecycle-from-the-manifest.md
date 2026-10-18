# An agent runs the whole lifecycle from the manifest alone

> This record predates the `prompt` command: the run prompted an inference endpoint the door no longer has
> (behavioralstate/spec#54). The run with the prompt as a command is recorded again on a GPU host under that slice.

The release gate of best-peer ([behavioralstate/spec#34](https://github.com/behavioralstate/spec/issues/34)): an LLM
client connected through the published connector signs in to the door, reads the manifest, checks the hardware,
deploys a model, follows the events, prompts the endpoint, runs a job and undeploys, with nothing written for it
beyond the manifest. This file is the record of the run that passed: how it was set up, what it showed, and the
transcript.

## The run

- **The door**: best-peer built from `7356234`, `BEST_PEER_RUNTIME=docker` on Docker Desktop (Linux containers), a
  fresh data directory, on a laptop with no accelerator adapter yet, so the hardware state shows the host CPU only.
- **The client**: GitHub Copilot CLI 1.0.96, non-interactive (`copilot -p`), on the model its Auto setting routed to
  (Claude Sonnet 5.5). The one MCP server added for the run was the published connector, `@behavioralstate/best-mcp`
  2.5.7, with no connection configured, `BEST_MCP_ALLOW_LOCAL=true` because the door was on loopback, and its
  credential file in a scratch folder deleted afterwards. The client's built-in GitHub servers were disabled; the
  owner's connectors to other services stayed loaded and none was called. Every call in the transcript is to a
  `best-peer-*` tool or to the client's own shell.
- **Nothing written for the agent**: the person's sentence at the top of the transcript is all it got. It read the
  manifest, both catalogues and three schema documents, and never saw this repository.
- **The person's part**: the agent showed the link and the code; at the machine, `best-peer approve 8BB9-CB44`
  admitted it (the approval's own log says 18:37:44, eleven seconds after the client started; the transcript
  carries no clock for it), and the agent's next poll had the credential, which it never saw.
- **The validator**: the tree the binary was built from passed `best-validate` 0.4.2 (BEST 0.9.17, conformant, 0 failures)
  anonymous and signed in, in the gate before the push and in CI on the commit.

## What the run showed

- Every step completed and nothing was refused: sign-in; the hardware state; the deploy (the engine image pulled in
  3 minutes 6 seconds, `DeploymentReady` with the endpoint 3 minutes 28 seconds after the command); a prompt
  answered at the endpoint with no door credential; a job run to `JobFinished` with exit code 0; the undeploy; an
  empty `get-workloads`.
- The agent read the schema documents, which list `completes`, then followed the deploy by polling `get_events` by
  `type` for the outcome it wanted (`DeploymentReady`, `DeploymentFailed`) rather than holding the stream; its one
  stream sample stopped at its own event cap among the progress events. For the job it polled `JobFinished`, the
  job's end, before `JobStarted`, the command's completion. Polling by type and correlation id was enough to drive
  the whole lifecycle.
- The job's output is not in the events (`JobFinished` carries the exit code only); the agent said so. Where a job's
  output goes is [behavioralstate/spec#39](https://github.com/behavioralstate/spec/issues/39).
- The door's own log for the run (not in the transcript, which holds only what the agent asked for) has 333 events,
  326 of them progress (`ImagePulling` 226, `WeightsLoading` 100), told at nearly every percent; that is more than a
  consumer needs: [behavioralstate/spec#40](https://github.com/behavioralstate/spec/issues/40).
- 38 tool calls in the transcript; 23 model turns and 5 minutes 9 seconds from the client's own log and summary.

## The transcript

Rendered from the client's own log: every message in order, tool calls numbered with their arguments, each result
under its call (shortened where it ran past a screen, event lists as one line per event). The credential appears
only as the connector's redaction.

---

**The person:**

> Sign me in laptop-peer, start from http://127.0.0.1:7777/.well-known/best. I am at the machine the door runs on: show me the link and the code, then wait for my approval and finish the sign-in.
> 
> Then, using only what that door's manifest and catalogues tell you, do the whole lifecycle and report every step with the call you made and what came back:
> 
> 1. Read the hardware state: what devices are there and what each offers.
> 2. Deploy the model qwen2.5:0.5b with the ollama engine and 1 GB of device memory.
> 3. Follow the events that command produces until it is ready or has failed. Pulling the image can take some minutes; keep following.
> 4. Send one prompt to the endpoint the ready event names (use curl for that; the door does not carry prompts) and show the model's answer.
> 5. Run a job with the image busybox and the command `echo hello from a job`, and follow it to its end.
> 6. Undeploy the model.
> 7. Ask the door what it runs now.
> 
> If a step is refused, say exactly what the door answered and what you did about it. Do not read source code or files on this machine, and never print any credential.

1. `best-peer-register_agent` {"name": "laptop-peer", "manifest": "http://127.0.0.1:7777/.well-known/best", "agent_label": "Copilot CLI on Riccardo's laptop"}

   ```
   {
    "name": "laptop-peer",
    "resolved": "http://127.0.0.1:7777/.well-known/best",
    "user_code": "8BB9-CB44",
    "verification_uri": "http://127.0.0.1:7777/auth/verify",
    "verification_uri_complete": "http://127.0.0.1:7777/auth/verify?user_code=8BB9-CB44",
    "expires_in": 600,
    "interval": 5,
    "next": "SHOW THE PERSON THE LINK AND THE CODE NOW, exactly as returned (verification_uri_complete already carries the code), and ask them to open it in their own browser: there they sign in — or sign up, where the service offers it — and approve you. Never open it yourself or in a browser you control: approving is theirs. Then call exchange_device_code with connection 'laptop-peer' and no device_code; while they have not acted it answers authorization_pending, which is not an error. The device code itself is held by best-mcp and is not shown."
   }
   ```

**The agent:** Open this link and approve: http://127.0.0.1:7777/auth/verify?user_code=8BB9-CB44
Code: **8BB9-CB44**

I'll poll for approval.

2. `best-peer-exchange_device_code` {"connection": "laptop-peer"}

   ```
   {
    "status": "authorization_pending",
    "interval": 5,
    "note": "Not an error. The person has not approved yet (or you polled too soon). Wait the interval in seconds, then call exchange_device_code with connection 'laptop-peer' again."
   }
   ```

3. `powershell` {"command": "Start-Sleep 30"}

   ```
   <command with shellId: 0 is still running after 30 seconds. The command is still running but hasn't produced output yet. You will be automatically notified when it completes; if you need the command to complete end your response with no tool calls to wait for the notification, or use stop_powershell to stop it.>
   ```

4. `read_powershell` {"shellId": "0", "delay": 5}

   ```
   
   <shellId: 0 completed with exit code 0>
   ```

5. `best-peer-exchange_device_code` {"connection": "laptop-peer"}

   ```
   {
    "access_token": "<stored by best-mcp — never shown to the model>",
    "auth_header": "X-Api-Key",
    "endpoint": "http://127.0.0.1:7777",
    "manifest": "http://127.0.0.1:7777/.well-known/best",
    "name": "laptop-peer",
    "ready_check": "http://127.0.0.1:7777/queries",
    "tenant_id": "127.0.0.1:7777",
    "token_type": "apikey",
    "session": {
     "connection": "laptop-peer",
     "connections": [
      {
       "name": "laptop-peer",
       "endpoint": "http://127.0.0.1:7777"
      }
     ],
     "signed_in_at": "http://127.0.0.1:7777/.well-known/best",
     "stored_under": "laptop-peer",
     "stored_at": "<a scratch folder of this machine>\\credentials.json",
     "note": "Signed in under 'laptop-peer'. Pass connection 'laptop-peer' on every call for this service — it works now and at every later start. The key itself was not returned and must never be typed into the conversation."
    }
   }
   ```

**The agent:** Signed in. Reading manifest and catalogues.

6. `best-peer-get_manifest` {"connection": "laptop-peer"}
7. `best-peer-get_query_catalogue` {"connection": "laptop-peer", "detail": "full"}
8. `best-peer-get_command_catalogue` {"connection": "laptop-peer", "detail": "full"}
9. `best-peer-get_workflows` {"connection": "laptop-peer"}

   ```
   {
    "client": "@behavioralstate/best-mcp 2.5.7",
    "manifestUrl": "http://127.0.0.1:7777/.well-known/best",
    "scope": "global",
    "manifest": {
     "best": {
      "authentication": {
       "deviceAuthorizationUrl": "http://127.0.0.1:7777/auth/device",
       "in": "header",
       "scheme": "X-Api-Key",
       "tokenUrl": "http://127.0.0.1:7777/auth/token",
       "type": "apiKey"
      },
      "capabilities": [
       {
        "description": "What this peer can be asked to do; the catalogue lists each command.",
        "name": "io.best.agents.commands",
        "schema": "https://behavioralstate.io/v1/schemas/agents/commands.json",
        "service": "io.best.agents",
        "spec": "https://behavioralstate.io/specs/agents/command
   … (1902 more characters)
   ```


   ```
   [
    {
     "dataschema": "http://127.0.0.1:7777/queries/get-hardware-state/1.0",
     "description": "The accelerators on this host right now: each device's compute APIs with their versions, its memory total and free, temperature, power and utilisation, and the driver. Read it before deploying: a model needs an API the device offers and memory it has free; get-workloads says what already holds memory.",
     "schema": "get-hardware-state",
     "version": "1.0"
    },
    {
     "dataschema": "http://127.0.0.1:7777/queries/get-workloads/1.0",
     "description": "What this peer runs now: each deployment with its model, engine, device, the memory promised to it, its inference endpoint once ready and its phase (starti
   … (193 more characters)
   ```


   ```
   [
    {
     "commandType": "PullImage",
     "dataschema": "http://127.0.0.1:7777/commands/pull-image/1.0",
     "description": "Makes a container image present on this peer, so a later deploy or job can start at once. The outcome is an ImagePulled or ImagePullFailed event with this command's correlation id.",
     "schema": "pull-image",
     "version": "1.0"
    },
    {
     "commandType": "DeployModel",
     "dataschema": "http://127.0.0.1:7777/commands/deploy-model/1.0",
     "description": "Serves a model on this peer with the engine named, on a device that offers an API the engine runs on and has the memory asked for free. Refused at once, with the reason and what to do, when no device fits. Otherwise the facts foll
   … (1592 more characters)
   ```


   ```
   This endpoint publishes no workflows.
   ```

10. `best-peer-execute_query` {"connection": "laptop-peer", "schema": "get-hardware-state"}
11. `best-peer-get_command_schema` {"connection": "laptop-peer", "schema": "deploy-model", "version": "1.0"}
12. `best-peer-get_command_schema` {"connection": "laptop-peer", "schema": "run-job", "version": "1.0"}
13. `best-peer-get_command_schema` {"connection": "laptop-peer", "schema": "undeploy-model", "version": "1.0"}

   ```
   {
    "devices": [
     {
      "compute": [
       {
        "api": "cpu"
       }
      ],
      "id": "cpu-0",
      "memory": {
       "free_bytes": 13502070784,
       "total_bytes": 30886772736
      },
      "name": "AMD Ryzen 9 6900HX with Radeon Graphics",
      "power_w": null,
      "temperature_c": null,
      "utilisation_pct": 5,
      "vendor": {
       "other": "host"
      }
     }
    ],
    "driver": null,
    "observed_at": "2026-10-12T17:38:21.7276234Z"
   }
   ```


   ```
   {
    "$id": "http://127.0.0.1:7777/commands/deploy-model/1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "commandType": "DeployModel",
    "completes": [
     "DeploymentEnded",
     "DeploymentFailed",
     "DeploymentReady",
     "OutOfMemory"
    ],
    "description": "Serves a model on this peer with the engine named, on a device that offers an API the engine runs on and has the memory asked for free. Refused at once, with the reason and what to do, when no device fits. Otherwise the facts follow on the stream with this command's correlation id: ImagePulling and ImagePulled, DeploymentStarted, WeightsLoading, then DeploymentReady with the OpenAI-compatible end
   … (1194 more characters)
   ```


   ```
   {
    "$id": "http://127.0.0.1:7777/commands/run-job/1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "commandType": "RunJob",
    "completes": [
     "JobFailed",
     "JobStarted"
    ],
    "description": "Runs an image once, with the arguments given, and tells its end. With memory_bytes the job is placed on a device with that much room and handed that device; without, it runs with no device. The facts follow with this command's correlation id: ImagePulling and ImagePulled, then JobStarted or JobFailed, which complete the command; the job's own end follows as JobFinished with the exit code, or JobFailed.",
    "produces": [
     "ImagePulling",
     "ImagePulled",
   … (712 more characters)
   ```


   ```
   {
    "$id": "http://127.0.0.1:7777/commands/undeploy-model/1.0",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "commandType": "UndeployModel",
    "completes": [
     "Undeployed"
    ],
    "description": "Stops a deployment and frees its device memory. Refused when no such deployment is live. The outcome is an Undeployed event with this command's correlation id.",
    "produces": [
     "Undeployed",
     "CommandFailed"
    ],
    "properties": {
     "deployment": {
      "description": "The deployment id from DeploymentStarted or get-workloads",
      "minLength": 1,
      "type": "string"
     }
    },
    "required": [
     "deployment"
    ],
    "title": "UndeployModel",
    "type": "object"
   }
   ```

**The agent:** Step 1: one device, cpu-0 (cpu API, 13.5 GB free of 30.9 GB). Deploying with 1 GB = 1073741824 bytes.

14. `best-peer-send_command` {"connection": "laptop-peer", "schema": "deploy-model", "version": "1.0", "data": {"model": "qwen2.5:0.5b", "engine": "ollama", "memory_bytes": 1073741824}}

   ```
   Command accepted. ID: 190f65b9-3e89-47bc-8bad-c03ab5c17ba1
   Correlation ID: 190f65b9-3e89-47bc-8bad-c03ab5c17ba1 — pass it as get_events / sample_event_stream params {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1"} to observe the outcome events.
   ```

15. `best-peer-sample_event_stream` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1"}, "max_seconds": 120, "max_events": 20}

   ```
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 6}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 8}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 9}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 10}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 11}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 12}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 13}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 15}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 16}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 17}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 18}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 19}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 21}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 22}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 23}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 24}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 26}
   17:38:26 ImagePulling {"image": "ollama/ollama", "progress_pct": 1}
   17:38:27 ImagePulling {"image": "ollama/ollama", "progress_pct": 2}
   17:38:27 ImagePulling {"image": "ollama/ollama", "progress_pct": 1}
   {"elapsedSeconds": 1.8, "endedBecause": "max_events reached", "note": "The stream is closed. Events arriving after this sample are not delivered — call again (passing lastEventId as last_event_id) to take another sample, or use get_events for history."}
   ```

**The agent:** Progress events are noisy; I'll poll for the terminal ones.

16. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "DeploymentReady"}}
17. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "DeploymentFailed"}}

   ```
   (no events)
   ```


   ```
   (no events)
   ```

18. `powershell` {"command": "Start-Sleep 90", "initial_wait": 100}

   ```
   
   <shellId: 1 completed with exit code 0>
   ```

19. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "DeploymentReady"}}
20. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "DeploymentFailed"}}
21. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "WeightsLoading"}}

   ```
   (no events)
   ```


   ```
   (no events)
   ```


   ```
   (no events)
   ```

22. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "ImagePulled"}}
23. `best-peer-sample_event_stream` {"connection": "laptop-peer", "max_events": 3, "max_seconds": 20, "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1"}}

   ```
   (no events)
   ```


   ```
   17:40:11 ImagePulling {"image": "ollama/ollama", "progress_pct": 65}
   17:40:12 ImagePulling {"image": "ollama/ollama", "progress_pct": 66}
   17:40:14 ImagePulling {"image": "ollama/ollama", "progress_pct": 67}
   {"elapsedSeconds": 3.4, "endedBecause": "max_events reached", "note": "The stream is closed. Events arriving after this sample are not delivered — call again (passing lastEventId as last_event_id) to take another sample, or use get_events for history."}
   ```

**The agent:** Pull at 67%, progressing. Waiting.

24. `powershell` {"command": "Start-Sleep 100", "initial_wait": 110}

   ```
   
   <shellId: 2 completed with exit code 0>
   ```

25. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "DeploymentReady"}}
26. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "DeploymentFailed"}}
27. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "190f65b9-3e89-47bc-8bad-c03ab5c17ba1", "type": "ImagePulled"}}

   ```
   17:41:54 DeploymentReady {"deployment": "dep-d90a5c5a8f24", "endpoint": "http://127.0.0.1:56935/v1", "engine": "ollama", "model": "qwen2.5:0.5b"}
   ```


   ```
   (no events)
   ```


   ```
   17:41:32 ImagePulled {"image": "ollama/ollama"}
   ```

**The agent:** Ready: dep-d90a5c5a8f24 at http://127.0.0.1:56935/v1. Sending a prompt.

28. `powershell` {"command": "'{\"model\":\"qwen2.5:0.5b\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in one short sentence.\"}]}' | Set-Content $env:TEMP\\p.json -NoNewline; curl.exe -s http://127.0.0.1:56935/v1/chat/completions -H \"Content-Type: application/json\" -d \"@$env:TEMP\\p.json\"; Remove-Item $env:TEMP\\p.json", "initial_wait": 90}

   ```
   {"id":"chatcmpl-878","object":"chat.completion","created":1791826925,"model":"qwen2.5:0.5b","system_fingerprint":"fp_ollama","choices":[{"index":0,"message":{"role":"assistant","content":"Hello, how are you today?"},"finish_reason":"stop"}],"usage":{"prompt_tokens":36,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens":8,"total_tokens":44}}
   <shellId: 3 completed with exit code 0>
   ```

29. `best-peer-send_command` {"connection": "laptop-peer", "data": {"image": "busybox", "args": ["echo", "hello from a job"]}, "schema": "run-job", "version": "1.0"}

   ```
   Command accepted. ID: fa27f22c-95c3-4e49-87f9-0c3bc7dd6938
   Correlation ID: fa27f22c-95c3-4e49-87f9-0c3bc7dd6938 — pass it as get_events / sample_event_stream params {"correlationId": "fa27f22c-95c3-4e49-87f9-0c3bc7dd6938"} to observe the outcome events.
   ```

30. `powershell` {"command": "Start-Sleep 20"}
31. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "fa27f22c-95c3-4e49-87f9-0c3bc7dd6938", "type": "JobFinished"}}

   ```
   
   <shellId: 4 completed with exit code 0>
   ```


   ```
   (no events)
   ```

32. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "fa27f22c-95c3-4e49-87f9-0c3bc7dd6938", "type": "JobStarted"}}
33. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "fa27f22c-95c3-4e49-87f9-0c3bc7dd6938", "type": "JobFailed"}}
34. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "fa27f22c-95c3-4e49-87f9-0c3bc7dd6938", "type": "ImagePulled"}}

   ```
   17:42:11 JobStarted {"container": "f73c6d150f43a7cbbcfd34936a9ae6ea1ca82f125a0b0535f7e8235269868a14", "device": null, "image": "busybox", "job": "job-453af372a3e0", "memory_bytes": 0}
   ```


   ```
   (no events)
   ```


   ```
   17:42:08 ImagePulled {"image": "busybox"}
   ```

35. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "fa27f22c-95c3-4e49-87f9-0c3bc7dd6938", "type": "JobFinished"}}

   ```
   17:42:11 JobFinished {"exit_code": 0, "job": "job-453af372a3e0"}
   ```

**The agent:** Job finished with exit 0. Undeploying.

36. `best-peer-send_command` {"connection": "laptop-peer", "data": {"deployment": "dep-d90a5c5a8f24"}, "schema": "undeploy-model", "version": "1.0"}

   ```
   Command accepted. ID: 2f6f07fe-b155-4333-8d6b-84e2beed5499
   Correlation ID: 2f6f07fe-b155-4333-8d6b-84e2beed5499 — pass it as get_events / sample_event_stream params {"correlationId": "2f6f07fe-b155-4333-8d6b-84e2beed5499"} to observe the outcome events.
   ```

37. `best-peer-get_events` {"connection": "laptop-peer", "params": {"correlationId": "2f6f07fe-b155-4333-8d6b-84e2beed5499"}}
38. `best-peer-execute_query` {"connection": "laptop-peer", "schema": "get-workloads"}

   ```
   17:42:37 Undeployed {"deployment": "dep-d90a5c5a8f24", "model": "qwen2.5:0.5b"}
   ```


   ```
   {
    "deployments": [],
    "jobs": []
   }
   ```

**The agent:** Every step completed and nothing was refused.

**Sign-in.** I called `register_agent` (name `laptop-peer`, manifest `http://127.0.0.1:7777/.well-known/best`). It returned the code `8BB9-CB44` and a link, which you approved. `exchange_device_code` first answered `authorization_pending`, then succeeded. The key is stored by best-mcp and never shown.

1. **Hardware.** I called `get_manifest`, both catalogues and `get_workflows` (no recipes published). I then ran query `get-hardware-state`. It returned one device, `cpu-0` (AMD Ryzen 9 6900HX), offering only the `cpu` API, with about 13.5 GB of 30.9 GB memory free. The driver was null.
2. **Deploy.** I sent `deploy-model` with `{model: "qwen2.5:0.5b", engine: "ollama", memory_bytes: 1073741824}`. It was accepted, with correlation ID `190f65b9-…`.
3. **Events.** `ImagePulling` ran for about 3.5 minutes, then `ImagePulled` and `DeploymentReady` arrived. The ready event named deployment `dep-d90a5c5a8f24` and endpoint `http://127.0.0.1:56935/v1`. There was no `DeploymentFailed`.
4. **Prompt.** I sent "Say hello in one short sentence." to `/v1/chat/completions` with curl. The model answered: "Hello, how are you today?"
5. **Job.** I sent `run-job` with `{image: "busybox", args: ["echo", "hello from a job"]}`, correlation ID `fa27f22c-…`. The events were `ImagePulled`, `JobStarted` (`job-453af372a3e0`, no device) and `JobFinished` with exit code 0. The output text isn't in the events, so I haven't seen "hello from a job" itself.
6. **Undeploy.** I sent `undeploy-model` with `{deployment: "dep-d90a5c5a8f24"}`. The door answered with an `Undeployed` event.
7. **Now.** Query `get-workloads` returned `{"deployments":[],"jobs":[]}`, so nothing is running.

