# best-peer

A peer is one binary on a machine with a GPU that puts that machine behind a
[Behavioral State Protocol](https://behavioralstate.io) door. An agent that knows only the door's manifest can read the
hardware state, deploy a model, follow its lifecycle on the event stream, prompt it with a command and read the
answer as an event, run a job and undeploy. Nothing is written for the agent beyond the manifest. The same door hosts workspaces, the
protocol's tenants: an organization or team creates one, invites the identities who may use it, and configures
clouds in it, named pools of peers whose owners admit the cloud at their console; a workload is placed in a cloud of
a workspace and every fact about it names the cloud, the peer and the device. Peers find, name and vouch for each
other through BEST doors too, so the same word carries to the end game: a network of peers and no centre.

best-peer is an implementation of BEST written in Rust from the spec text alone, sharing no code with any other, so
the spec is proven portable and its gaps surface. It wraps an existing runtime (containers with the NVIDIA container
toolkit running Ollama or vLLM) and builds no engine of its own. A prompt is a BEST command and its answer a BEST
event; the peer reaches the engine's own API behind an abstraction it owns, and nothing of the engine is on the door:
BEST carries the whole of it.

The plan is the epic [behavioralstate/spec#27](https://github.com/behavioralstate/spec/issues/27) and its slices, on the
[Behavioralstate board](https://github.com/orgs/Amarcode-Studios/projects/4). The board is the plan: no plan file lives
here. How the work is made and shipped is [SDLC.md](SDLC.md).

Done means `best-validate` green on the served manifest and an agent running the whole lifecycle from the manifest
alone, with the transcript kept in this repository: [acceptance/lifecycle-from-the-manifest.md](acceptance/lifecycle-from-the-manifest.md)
is that record, made with the published connector and a client that had nothing but the person's sentence.

## Try it on your machine

The path for someone handed a release binary: a Linux PC with an NVIDIA card is the first-class case, and the
other cases are one variable away. What the terminal shows at each step is written here so a run that differs is a
finding worth sending back.

**Before you start.** The peer reads the card through the NVIDIA driver, so a GPU host needs the driver installed
and loaded; the peer refuses to start without it. A host with no card (a laptop, a Mac) sets `BEST_PEER_GPU=none` and
the CPU is the one device. Then one of two ways to run models, each with what it asks of the machine:

| Way | What the machine needs | Settings |
|---|---|---|
| **Docker** (the default) | Docker Engine running and reachable by your user (`docker ps` without `sudo`, or run the peer with it), and the NVIDIA container toolkit registered with it, so that `docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi` lists the card. Room under Docker's storage for the engine image and the model weights, a few GB. | None: the peer pulls the engine image, starts the container, publishes its port. |
| **Native** | Ollama installed and running as a service on its own port. The peer pulls the model through it and claims its port; nothing is started or stopped. No jobs: `run-job` is refused at ingest, with the fix. | `BEST_PEER_RUNTIME=native`. Ollama keeps its own bind, loopback as installed: a prompt reaches it as a command through the door. |

`BEST_PEER_RUNTIME=fake` is a third way for a machine with neither: the surface answers, nothing runs. Every other
variable has a default that fits these two ways; [Run](#run) lists them for a setup that differs.

**1. Download and run.** Take the newest release's archive for your machine, unpack it, and start the peer:

```bash
curl -fLO https://github.com/behavioralstate/best-peer/releases/latest/download/best-peer-x86_64-unknown-linux-gnu.tar.gz
tar xzf best-peer-x86_64-unknown-linux-gnu.tar.gz
cd best-peer-x86_64-unknown-linux-gnu
./best-peer --version
./best-peer
```

On Windows x86_64 the archive is `best-peer-x86_64-pc-windows-msvc.zip`, on macOS Apple silicon
`best-peer-aarch64-apple-darwin.tar.gz`. The [releases](https://github.com/behavioralstate/best-peer/releases) page
holds the same archives under names that carry the version, for pinning one, with `SHA256SUMS` to check them against.

It prints one line, `best-peer is serving its door`, with where it listens and its data folder, and then waits:
nothing else appears until a client talks to it. If it exits instead, the message names what is missing (the
driver, Docker) and the variable that serves without it. `http://127.0.0.1:7777/.well-known/best` in a browser is
the manifest, the one document an agent needs.

**2. Let someone reach it.** By default the peer listens on loopback, so only clients on the same machine see it.
For a person elsewhere, listen on every interface and say the address they will reach, as `https://`:

```bash
BEST_PEER_LISTEN=0.0.0.0:7777 BEST_PEER_ENDPOINT=https://<address they reach>:7777 ./best-peer
```

The peer makes itself a certificate at first start, keeps it in its data folder and names the file in the line
`https with a certificate this peer made`: send that file to the person connecting, and their client trusts it
(`NODE_EXTRA_CA_CERTS=<file>` for a Node client, `SSL_CERT_FILE=<file>` for a Python one, `--cacert <file>` for
curl). A certificate of your own, from your CA or a public one for a name you hold, is
`BEST_PEER_TLS_CERT=<chain.pem> BEST_PEER_TLS_KEY=<key.pem>`; the peer checks nothing about it beyond that it
loads. An `http://` endpoint is served on loopback alone: off it the credential would travel in the clear, and the
peer refuses to start, saying what to set. A hop that a VPN already encrypts (a WireGuard or Tailscale address) is
the one exception, and you say so: `BEST_PEER_CLEARTEXT=vpn` serves `http://` off loopback, with a warning at start,
and lets this door's clouds reach members over `http://`. Behind a proxy, let it pass TLS through, or re-encrypt to
the peer's own certificate. There is no relay in the peer, so across the internet the address is one you make
reachable (a static IP with a port forward, a Tailscale IP), and the firewall lets in 7777 and nothing else: a prompt
is a command on the door like any other, on that port, with the door's credential. The engines' own ports stay on
loopback whatever the door listens on, and nothing of them is on the door.

**3. Admit the agent.** The person connecting says to their client "sign me in `<name>`, start from
`https://<address>:7777/.well-known/best`"; their client shows them a code like `8BB9-CB44`, and they send it to you.
At your machine:

```bash
./best-peer approve 8BB9-CB44
```

Their client's next poll receives a key under that name. No accounts, no passwords: whoever controls the machine
decides who is in, as with SSH keys, and what they may do: approved with nothing more said, a key may do everything;
`--may deploy,prompt --memory 40G` makes one that may deploy models and prompt them but run no job, and hold 40 GiB
of device memory at most across its workloads, which it alone sees, prompts and ends. `--deployments 2 --jobs 2` lets it
run two of each at once at most. A key with a share runs its jobs in a closed box (no network, a ceiling on host
memory) unless you add `--open-jobs`. `--expires 8h` ends the key after eight hours, so access lent for an afternoon
ends without anyone remembering to take it back. To take a key back sooner, at your machine:

```bash
./best-peer revoke <name>
```

with the name it was approved under: every request carrying it is refused from then on, and an event stream it holds
open ends within seconds. The agent can also give its key back itself, with the `revoke-agent` command.
`--accelerators-only` holds a key to the accelerators, never the host's CPU.

A code waits ten minutes for you; the door holds at most five waiting from one client, sixteen from one address and 64 in all, and past that
answers 503 with how long until the oldest expires. An IPv6 address is counted by its /64, which one client holds
whole, and a connection whose address is not known is counted with every other such one. Loopback is not counted at
all: it is this machine, so a proxy on this machine in front of the door takes the per-address ceiling away, and a
proxy on another machine puts every caller behind it under one count of sixteen. The door reads no forwarded
address, since any client can write one; with a proxy, set the ceiling per address there.

**4. More than one machine.** Run a peer on each, and one more `best-peer` anywhere as the door your team enters
by: a laptop will do, with `BEST_PEER_GPU=none` and the runtime it has (`BEST_PEER_RUNTIME=fake` when it has none:
its own device then serves nothing real, and the clouds are what the door is for), and
`BEST_PEER_TRUST=<a's cert.pem>,<b's cert.pem>` when the machines serve their own certificates. The pool is made through that door, by the agent, from the manifest alone: the
person says "create a workspace called research, then configure a cloud called lab in it with the peers
a=https://<machine a>:7777 and b=https://<machine b>:7777". The agent sends `create-workspace` at the root, reads
the workspace's endpoint from `get-workspaces`, and sends `configure-cloud` there. The door signs in to each
machine as any agent would and logs the code for its owner: `to admit cloud lab of workspace ws-… on a, run on that
machine: best-peer approve <code>`. Once admitted, the machine is `up` in the workspace's `get-clouds` and its
devices are in its `get-hardware-state` as `lab/a/gpu-0`; a deploy in the workspace names the cloud and goes to
the peer with the room, every fact comes back on the workspace's stream with the cloud and the peer named, and a
prompt in the workspace is placed on the peer that holds the deployment and answered on the same stream. A machine that stops answering is `PeerLost` on
that stream, with every workload it held told as ended, and `PeerJoined` when it answers again. The same machine
may serve a cloud of another workspace too; one cloud per workspace. Who else may use the pool is the owner's to
say: `invite-member` with the identity their `get-workspaces` shows them, and they `accept-invitation`. A door
started with `BEST_PEER_MEMBERS` set refuses to start and names these commands: the pool is configured through the
door, not the process.

**5. What the agent does from there.** Reads the hardware state (a card shows its memory, temperature, power,
utilisation and the CUDA version; the host CPU is listed after it), deploys a model on it, follows the events to
`DeploymentReady`, sends it a `prompt` and reads `PromptAnswered`, runs a job, undeploys. The run as recorded the
first time it passed is [acceptance/lifecycle-from-the-manifest.md](acceptance/lifecycle-from-the-manifest.md); it
prompted an inference endpoint the door no longer has, and the run with the prompt as a command is recorded again on
a GPU host under behavioralstate/spec#54. Send back the terminal output of the peer, whatever happened: the release
notes say what is proven and what is not yet.

## Layout

| Crate | What it owns |
|---|---|
| `crates/door` | The BEST surface, from the spec text: the manifest, the catalogues and schema documents, command ingest with refusals that say what to send and an idempotent `id`, the event log on disk with its paged history and its live stream, queries, workflows, and sign-in by the device flow with the guidance verbatim; a door that hosts tenants declares their manifests' template and serves each tenant's capabilities as a door of its own. Who approves is an `Approver` the peer chooses. |
| `crates/gpu` | The accelerator abstraction: a vendor-neutral snapshot of the host's devices (`Gpu`), each naming the compute APIs it offers (CUDA, ROCm, oneAPI, Metal, Vulkan, CPU) so a workload asks for an API and memory, never for a vendor. Ships the `Fake` tests run against. |
| `crates/runtime` | The container runtime abstraction (`Runtime`): pull with progress, start with devices handed over by id and the ports published, stop, observe, and what the engine does on its own told as events. Ships the `Fake`. |
| `crates/engine` | The inference engine abstraction (`Engine`): which engines serve a model (Ollama, vLLM), what to run for each, how a served model is made ready, with progress, and how it is asked to answer a conversation. Ships the `Fake`. |
| `crates/peer` | The `best-peer` binary: the door over the three abstractions, with the peer's own commands, queries and events, its state folded from the events it told; the workspaces it hosts, each a tenant door with its clouds of peers, folded from their own logs; and `best-peer approve` and `best-peer revoke`, the operator's side of sign-in. |
| `crates/host` | The host itself as a device: a `Gpu` adapter reporting the CPU and system memory, so a peer with no accelerator serves the whole lifecycle. |
| `crates/nvml` | The `Gpu` adapter for NVIDIA cards through NVML: memory, temperature, power, utilisation and the CUDA version, read live; the peer refuses to start without the driver unless told the host has none. |
| `crates/docker` | The `Runtime` adapter over the Docker Engine API: NVIDIA devices handed over through the container toolkit by their NVML UUID. |
| `crates/native` | The `Runtime` adapter for engines already running on the host outside any container (an installed Ollama): a deploy binds to the engine's own port; jobs need Docker. |
| `crates/engine-http` | The `Engine` adapter over the engines' own HTTP APIs. |

The three adapters are thin and proven on a host by hand, with the proof on the slice's issue; they are never
unit-tested and CI runs on the fakes. Accelerator adapters (NVML, ROCm) are separate crates too, and join the same way.

## Run

```bash
cargo run -p best-peer                        # on a host with the NVIDIA driver
BEST_PEER_GPU=none cargo run -p best-peer     # on any other machine: the CPU is the one device
curl http://127.0.0.1:7777/.well-known/best
npx -y @behavioralstate/best-validate http://127.0.0.1:7777
```

Or take a [release](https://github.com/behavioralstate/best-peer/releases), as in [Try it on your machine](#try-it-on-your-machine):
one binary per machine (Linux x86_64 on glibc 2.35 or newer; Windows x86_64; macOS Apple silicon), with `SHA256SUMS`
and a build provenance attestation (`gh attestation verify <archive> --repo behavioralstate/best-peer`).
`best-peer --version` says which it is.

`BEST_PEER_LISTEN` (default `127.0.0.1:7777`) is where it listens; `BEST_PEER_ENDPOINT` is the consumer-facing base URL
the manifest advertises, required when the peer listens on every interface. An `http://` endpoint is served only
when both the listen address and the endpoint's host are loopback (`127.0.0.0/8`, `::1`, `localhost`); otherwise the
peer refuses to start, naming which is off, unless `BEST_PEER_CLEARTEXT=vpn` says a VPN already encrypts every hop to
and from it, which also lets its clouds reach members over `http://`. An `https://` endpoint is served by the
peer itself, with rustls: `BEST_PEER_TLS_CERT` and `BEST_PEER_TLS_KEY` name the operator's certificate chain and
private key (PEM files, checked for nothing beyond loading); without them the peer makes a certificate at first
start, `tls/cert.pem` under its data folder, named at start for clients to pin, and made again when the endpoint's
host changes or fewer than thirty days of it remain, which the start-up line says. `BEST_PEER_DATA` (default
`~/.best-peer`) holds the event log, the credentials as hashes, the admin token, that certificate, and the record of
where the door is that `best-peer approve` reads, so it reaches the peer over the same TLS, pinned to that
certificate and no other.
Every request to the door, a workspace's included, is one line in the peer's log at info: where it came from (the
client's address and port, so the log holds the addresses of everyone who reached the door), the method and the
path as it arrived (never the query string), the status, the holder when a credential opened it, refused or not,
and how long the answer took. The key is never in it. A request the client gave up on before its answer is a line
too, `request abandoned` with the status `-`; an event stream's line is written when it opens, and its `ms` is the
time to the headers, not how long it stayed open. The log is loud by design: an agent's polls, a cloud's ticks and
every stream reconnect are lines. The lines are under the target `best_peer_door::router`, so
`RUST_LOG=info,best_peer_door::router=warn` quiets them and keeps everything else. The peer writes its log to
stderr and keeps no file of its own: the record lasts as long as whatever runs the peer keeps stderr (journald under
systemd, by its own size and age limits), so an operator who counts on it as an audit trail sets that retention.

Every door hosts **workspaces**, the BEST tenants. The root manifest declares their template
(`/.well-known/best/{tenantId}`), and a workspace's own door is at `/workspaces/<id>` under the root, with its own
log, catalogue, stream and correlation space; a credential opens the workspaces it belongs to and nothing of the
others, and `get-workspaces` at the root lists them with each one's endpoint and manifest. At the root:
`create-workspace` (whoever sends it is the owner), `invite-member` (the owner, naming the invitee's `identity`,
the opaque id of their credential that `get-workspaces` shows them), `accept-invitation` and `leave-workspace`
(refused while one still holds a workload there); owner and member are the only roles, and the owner stays. The
root's events tell a credential the membership facts addressed to it by identity (the workspace it made, the
invitations it received or sent, its own joins and leaves) and nothing of another workspace, whatever its grant;
a workspace's own stream tells its members its membership, its clouds and its peers, and each holder its own
workloads. In a workspace: `configure-cloud` names a **cloud**, a
pool of peers as `peer` and `endpoint`, and makes or changes it (one machine serves one cloud per workspace, and a
peer still holding a workload is not removed); `archive-cloud` retires an empty one, and `get-clouds` lists them
with each peer's state. The cloud signs in to each member by the device flow and logs the code to approve there;
the credentials and its place on each member's stream live in `workspaces/<id>/clouds/<cloud>/members.json` under
the data folder. The workspace's `get-hardware-state` lists every cloud's devices as `cloud/peer/device` with the
peers and their state; `deploy-model`, `run-job` and `pull-image` take the `cloud` (a `device` names it too) and
are placed by the peer's own rule across its members and sent there as the cloud's command; what a member tells
comes back on the workspace's stream under the caller's correlation id with `cloud` and `peer` named; a prompt is
placed on the member that holds the deployment, as the cloud's own command there, and its answer relayed the same
way. `BEST_PEER_TRUST` lists PEM files to trust beyond the public roots, for members serving their own
certificates. A member named by an `http://` endpoint off loopback is refused at `configure-cloud`
(`CLEARTEXT_MEMBER`), and nothing is sent to one, since the cloud's credential would travel in the clear, unless this
door's operator set `BEST_PEER_CLEARTEXT=vpn`. A cloud recorded with such a member before (under an older peer, or
while `vpn` was set) stops the peer at start, naming the workspace, the cloud, the peer and its endpoint, and how to
name it by `https://` instead. Every thirty seconds each cloud squares its state with its members: one that does not answer within
fifteen seconds is told as `PeerLost`, with its workloads told as ended and its commands in flight failed;
`PeerJoined` when it answers again, and what it still runs of the cloud's by then is ended there, so the two agree;
a workload a member no longer lists at two ticks running is told as ended. A credential's share is counted across
the whole door: its workloads at the root and in every workspace together.

`BEST_PEER_GPU` (default `nvml`) is how the peer sees the hardware: through the NVIDIA driver's own library, every
card with its memory, temperature, power, utilisation and the CUDA version the driver offers, read live at every
query, and the host CPU with the system memory listed after the cards; a host without the driver is refused at
start, with the fix. `none` says this host has no accelerator, and the CPU is the one device.

The container engine is Docker on the same host, reached through its socket or named pipe; the peer refuses to start
without it unless `BEST_PEER_RUNTIME` says otherwise: `native` deploys to an engine already running on the host
outside any container (an installed Ollama; no jobs), `fake` serves the whole surface against the in-memory fakes
(what CI runs).
A deploy or a job pulls an image named by tag each time, since a tag may have moved, as before; one pinned by digest
(`name@sha256:...`, handed to Docker whole) names one image for good and is pulled only when Docker does not hold it.
`BEST_PEER_PULL=missing` pulls any image only when Docker does not hold it: for a host with no way to a registry,
whose images were put there by hand, a held image then runs as it is and is refreshed only by `pull-image`, which
always pulls. Either way a credential may run any image Docker holds, the operator's own and locally built ones
included, by naming it: a host shared with a tenant keeps in Docker only the images it would let that tenant run.
`BEST_PEER_OLLAMA_IMAGE` and `BEST_PEER_VLLM_IMAGE` pin or mirror the engines' images; `BEST_PEER_READY_SECONDS`
(default 900) is how long an engine may take to answer after its container started, `BEST_PEER_LOAD_SECONDS`
(default 3600) how long a model may take to load, and a prompt is given ten minutes to be answered. `BEST_PEER_ENGINE_HOST` (default `127.0.0.1`) is where the peer
itself reaches the engines' ports, which are bound there and nowhere else whatever the door listens on: on loopback
when the container engine is on this host, on that host's interfaces when it is elsewhere, so a container engine
on another host sits on a network you trust. The peer alone reaches them: a prompt is a command on the door, and
the peer carries it to the engine. Prompts are answered sixteen at a time per peer; the rest wait their turn,
accepted, in order. How many deployments and jobs a key runs at once is set when it is approved
(`--deployments`, `--jobs`); a peer started with the old `BEST_PEER_DEPLOYMENTS_PER_HOLDER` or
`BEST_PEER_JOBS_PER_HOLDER` refuses to start and says so. `BEST_PEER_COMMANDS_PER_MINUTE` (default 60) is how many
new commands one credential with a share may send in any sixty seconds across the door, and
`BEST_PEER_STREAMS_PER_CREDENTIAL` (default 4) how many event streams it may hold open; a number below 1 is refused at start.

A container runs confined: no capabilities, no new privileges, a ceiling on tasks (every thread counts as one), and
a small init as its first process, which reaps what the image leaves behind and passes a stop on to it. The job of a
credential approved with a share, a tenant's, runs code the owner did not write, so it also gets a closed box: a
read-only filesystem with a private `/tmp` of 1 GiB, which counts in its memory, no network, and a ceiling on host
memory with swap counted in. The owner's own jobs, from a credential with no share, keep the network, a writable
filesystem and the host's memory, as before; so do a tenant's whose approver said `best-peer approve --open-jobs`,
which only the approver can say, never the credential or the job. `JobStarted` says `boxed`.
`BEST_PEER_JOB_MEMORY` (default `4G`) is the box's host memory ceiling and `BEST_PEER_JOB_PIDS` (default 4096) every
job's task ceiling, `BEST_PEER_ENGINE_MEMORY` (default none) and `BEST_PEER_ENGINE_PIDS` (default 4096) an
engine's; `none` is no ceiling, and a memory ceiling under the 6M a container starts with is refused at start. Host
memory is not device memory: a boxed job that reaches its ceiling ends in `JobFailed` naming it, whatever
`memory_bytes` it asked for. The engines keep their network, which they need to pull models, and a writable
filesystem, which they keep the models on. Capabilities, privileges and the box are never opened by a variable. On a
workspace's cloud, a job runs on the member as the cloud's credential: boxed when the member's owner approved the
cloud with a share and did not open its jobs.

`BEST_PEER_MODEL_STORE` names a store of models beside the registry: Ollama's library (`blobs/` and `manifests/`,
what `OLLAMA_MODELS` holds after an `ollama pull`). A deploy on Ollama of a model the store holds is served from it,
the store mounted read-only at `/models`, and pulls nothing; a model the store lacks is pulled from the registry as
before. The peer looks for the model's manifest in the store itself before it starts the engine, so the store is a
directory at the same path for the peer and the container engine, which it is when they share a host; one the peer
cannot read refuses the start. vLLM is not served from a store: it pulls as before. A store is for containers: with
`BEST_PEER_RUNTIME=native` or `fake` the peer refuses to start. An embedding model cannot be deployed from it, since
a deployment answers conversations. A tenant told that a model failed reads of "the operator's model store", never
its path.

## Deploy

Everything an agent needs is in the catalogues. `get-hardware-state` says what devices are here and what each offers;
`get-workloads` says what already holds memory on them. `deploy-model` names a model, an engine (`ollama` runs on
CUDA, ROCm or CPU; `vllm` on CUDA) and the device memory it needs; the peer places it on a device offering an API the
engine runs on with that much room after what is already promised, or refuses at once with the reason and what to do.
On a workspace's door the same commands take the `cloud` to place in (or a `device` as `cloud/peer/device`, which
names it), the devices are every cloud's peers', and every row and event carries `cloud` and `peer`.
The facts follow on the event stream under the command's correlation id, in order: `ImagePulling`, `ImagePulled`
(`held: true` when the image was already here and not pulled, `ImagePulling` then told once, at 100),
`DeploymentStarted`, `WeightsLoading`, then `DeploymentReady`, or `DeploymentFailed`. What the engine does on its own
later (`OutOfMemory`, `DeploymentEnded`) is told under the same correlation id. `prompt` names a ready deployment and
the conversation so far, and `PromptAnswered` follows under its own correlation id with the answer whole, or
`PromptFailed` with the reason and the fix. `run-job` runs an image once, a tenant's in a closed box, and tells
`JobStarted` and `JobFinished` with the exit code; `undeploy-model` and `stop-job` end them.

The peer's state is the fold of the events it told. After a restart it is rebuilt from the log and squared with what
the engine still runs; a workload that ended while the peer was down is told so then.

## The data path

BEST carries the whole of it. A deployment is prompted with a command, `prompt`, naming the deployment and the
conversation so far (messages with their role and content, and the engine's knobs: `max_tokens`, `temperature`,
`stop`), and the model's answer is a fact, `PromptAnswered`, under the prompt's correlation id, with the answer whole,
the model that answered and the token counts the engine reported; `PromptFailed` says why there is no answer and what
to do. The peer reaches the engine's own API behind the `Engine` abstraction, on the loopback port the runtime
published, and nothing of the engine is on the door: there is no inference endpoint, no path under a deployment, no
header the engine would read. A prompt needs the `prompt` scope and a deployment that is ready and the caller's,
refused at ingest otherwise with what to do. The answer is one fact, not one per token: a token is not a fact about
the machine, and streaming partial output is not here (behavioralstate/spec#54 says what is and what waits). What the
engine is asked and what it answers are in the door's log like every other fact, read by the holder under its own
correlations and by nobody else (behavioralstate/spec#53).

Where the boundary lies: the engines' own ports are bound to loopback whatever the door listens on (in `native` mode
the installed engine keeps its own bind), and the peer is the one thing that reaches them. A prompt on a deployment
that is not ready, or whose `undeploy-model` was accepted (its phase is `ending` in `get-workloads` from then, and
`Undeployed` follows), or that nobody made, is refused at ingest with what to do; an engine that does not answer
within ten minutes is `PromptFailed` with the fix. The door promises that a ready deployment answers prompts from
`DeploymentReady` until the deployment ends: the undeploy, or `DeploymentEnded` or `OutOfMemory` telling what the
engine did on its own, within 30 s of it where the engine told nothing itself. What the model says is the model's.

## Commands over time

Every command of this peer follows one pattern, and nothing else is needed to drive it:

1. `POST /commands` answers `201` with the correlation id, once the command passed its schema and the peer's
   current state (a deploy no device has the memory for is refused here, not failed later). A correlation id
   belongs to the credential that first used it on this door, and a command's `id` serves as its correlation when
   it names none: another credential naming either is refused with the field and the fix, since what a credential
   reads is the facts under its own correlations. A chain of commands under one correlation is one credential's. From that moment the
   command ends in a completing event, through a restart if need be: a command accepted and not yet run when the
   peer stops is run when it starts again, through the same state check, or failed with a `CommandFailed` that
   says why; one whose workload had already started and did not survive the restart is failed with the fix. The
   door keeps the command whole until it completes, then only its id, hash and correlation, which still answer a
   retry as before, in memory and after a restart alike.
2. Everything that happens is an event carrying that correlation id, in the order it happened. The command's
   schema document lists what it `produces` and, among those, what `completes` it: the events after which the
   command's outcome is known (`DeploymentReady` for a deploy, or `DeploymentFailed`, `DeploymentEnded` or
   `OutOfMemory` when it ended before it was ready; `JobStarted` or `JobFailed` for a job), so a consumer stops
   waiting for the command and a restart does not run it again; the others are
   progress on the way (`ImagePulling`, `WeightsLoading`, with `progress_pct` where the engine says).
   `CommandFailed` completes any command.
3. What the command made then has a life of its own, told under the same correlation id (`JobFinished` with the
   exit code, `OutOfMemory`, `DeploymentEnded`), so one filter follows it from the first event to the last.
4. A consumer that was not listening catches up with `GET /events?correlationId=...`, following `nextCursor` to
   the end, and follows from there with `GET /events/stream` and `Last-Event-ID`. There is no other channel for
   progress or outcome, and nothing to poll.

A credential with a share holds 4 event streams open at once at most, counted across the door and every workspace
on it (`BEST_PEER_STREAMS_PER_CREDENTIAL`); opening a fifth ends its oldest, which reads to its client as a stream
that closed, so it reconnects with `Last-Event-ID` and misses nothing. Nothing is refused: a client whose connection
died without a close (a dropped Wi-Fi, a laptop asleep) still holds its stream until the door's writes to it fail,
which can take minutes, and its reconnect takes the ghost's place instead of meeting it. Reconnecting costs the
replay since its last id. One stream without `correlationId` follows everything the credential may read. A cloud
holds one stream on each member. A credential without a share, the owner's, is not counted.

A credential approved with a share (`--memory`), the tenant's kind, sends 60 new commands in any sixty seconds at
most, counted across the door and every workspace on it (`BEST_PEER_COMMANDS_PER_MINUTE`): the one past that is
refused with `TOO_MANY_COMMANDS`, 429 and `Retry-After`, and was not accepted. A credential without a share, the
owner's own, is not paced, so an evaluation or a batch of prompts runs as fast as the peer answers. A retry of an
accepted command is answered as it was and is not counted, nor is a command refused before it is whole or by its
admission (no room, no such workload). On a member, a cloud is one credential: when the member's owner approved it
with a share, every tenant of the cloud shares the member's pace, and a member that refuses the cloud's command is
told on the cloud's stream as the command's failure, with the member's reason, so a member's owner who hosts a busy
cloud raises the pace or approves the cloud without a share.

Every string and list a command carries has a bound its schema document states (`maxLength`, `maxItems`), refused
past it with `SCHEMA_VALIDATION` naming the field. A request body weighs 256 KiB at most on the door and 4 KiB less
on a workspace's, refused with `PAYLOAD_TOO_LARGE` and `limit_bytes`: a cloud passes a command on to a member's door
in an envelope of its own, so whatever the cloud took, the member takes.

## Sign in

An agent signs a person in the way every BEST service is signed in to: it reads the manifest, posts to
`deviceAuthorizationUrl`, gives the person the link, and polls `tokenUrl`. The published connector does this by itself.

Who may use a peer is decided by whoever controls the machine it runs on, as with SSH keys: no accounts, no passwords,
no identity provider. The page the person opens shows the code and says what to do; on the peer's machine:

```bash
best-peer approve ABCD-EFGH
```

That presents the machine's admin token, which only its owner can read, and the agent's next poll gets its credential:
a key shown once, kept hashed, bound to the connection name the person gave. The token is checked before anything
else, so without it an approval learns neither whether a code is pending nor which scopes the door has. An operator
who wants an identity provider instead plugs one in behind the `Approver` trait, which says whether a proof is the
authority's (`attest`, asked first, and for a revoke) and admits a registration (`admit`); the door never knows which
stands behind it.

**Where a credential belongs** is the workspaces it created or accepted an invitation into, on this door, and
`get-workspaces` says which, with the identity the credential is known by there, an opaque id another workspace's
owner names to invite it; the token answer's `endpoint` is the root, where that query is. A credential that has not
joined any workspace still uses the machine's own surface at the root.

**What a credential may do** is set at the approval and travels with the key. The manifest's authentication block
lists the scopes: `deploy` (pull-image, deploy-model, undeploy-model), `jobs` (run-job, stop-job) and `prompt`
(prompt); `all` is every scope and every holder's workloads, and what a key approved with nothing said is, so the owner's own box changes
nothing. Reading is every key's: the hardware state, and its own workloads and events. `best-peer approve <code>
--may deploy` grants scopes; `--memory 40G` sets the most device memory the key's workloads may hold together,
counted across its deployments, jobs and commands admitted but not yet started; `--expires 8h` ends the key after
that long (`8h`, `30m`, `2d`, or seconds; 366 days at most, and 8 hours at most for a session credential, which an
agent asks for when it cannot keep a secret: more is refused, never cut). `best-peer revoke <name>` takes a key back
at once, by the connection name the agent signed in under or the holder id the events show, with the peer running
and the same admin token; an agent takes back its own with the `revoke-agent` command, sent under it. Either way the
key opens nothing from then on, on this door and every workspace door here, an event stream open under it ends
within seconds, as one does when a key runs out, and what the key left running is the owner's to end. A revoke the
disk did not keep says so: the key is closed until the peer restarts, and running the revoke again writes it. Every command document says which
scope it needs. A command the key may not send is refused at ingest with `FORBIDDEN` and what it was approved for;
a deploy or a job past the share with `SHARE_EXCEEDED`, what is held and the room left; a workload another key
started, by name, whether a command, a prompt or the events are asked for, and a refusal names only what the key may
see. `get-workloads` shows a key its own, with `held_bytes` against `share_bytes`; `DeploymentStarted` and
`JobStarted` name the `holder`, an opaque id of the credential, never the key. A key with a share runs its jobs on
a device, where its share counts them: a job without `memory_bytes`, which would run on the host with no device and
hold the host's memory and processors outside the share, is refused with `JOB_NEEDS_DEVICE`; a key with scopes and
no share is not held to it. In a workspace the rule holds for the cloud's jobs, and a member's owner who approved the
cloud with a share holds every tenant of the cloud to it on that member. A key approved with `--deployments N` or
`--jobs N` runs that many deployments or jobs at once at most, counted across the door like the share, every
workspace's included, and the one past that is refused with `DEPLOYMENTS_EXCEEDED` or `JOBS_EXCEEDED`: what a
workload claims in `memory_bytes` is its client's own word, so the share bounds what is promised and the counts how
many, while neither bounds what a workload uses on a card that cannot be partitioned. A key approved without them is
not counted. On a member the cloud's own credential is one holder, so a member's owner who approved the cloud with a
count counts every tenant of the cloud together, and a deploy the cloud accepted can then be refused by the member,
told on the workspace's stream as `DeploymentFailed` with the member's reason. A key approved with `--accelerators-only`
sees and uses the accelerators alone, so the host's CPU and memory stay the operator's: `get-hardware-state` shows it
only those, and a device that offers the CPU alone, or a host with no accelerator, is refused with
`ACCELERATORS_ONLY` and what it may name instead. A share does not imply it: a key approved with `--memory` alone may
still be placed on the CPU device, within its share. In a workspace the rule holds for the cloud's devices, and a
member's owner who approved the cloud with `--accelerators-only` holds every tenant of the cloud to that member's
accelerators. Another sign-in is another holder, as the spec has it: what a key that expired or was
replaced left running is the owner's to end with a key approved for all. The spec has no per-command scope field
yet, so the requirement is in the description text; that is an entry on the spec follow-ups.
