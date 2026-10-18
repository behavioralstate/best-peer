#!/usr/bin/env bash
# Proves the NVIDIA adapter and the Docker device hand-over on a GPU host, by hand, the way SDLC.md asks for every
# adapter: the peer is started with the driver's library, the hardware state is read, a model is deployed on a card
# in a container, prompted with the prompt command, and undeployed. The transcript it prints is what goes on the slice's
# issue. Needs: a best-peer binary (a release archive, or a dry run's artifact), Docker with the NVIDIA container
# toolkit, curl and python3. Nothing else is configured; the peer is approved from this same shell.
#
#   scripts/gpu-host-proof.sh [path to best-peer] [model]      default: ./best-peer, qwen2.5:0.5b
set -uo pipefail

exe="${1:-./best-peer}"
model="${2:-qwen2.5:0.5b}"
[ -x "$exe" ] || { echo "no executable at $exe (on Windows, give best-peer.exe)"; exit 2; }
data="$(mktemp -d)"
export BEST_PEER_DATA="$data" BEST_PEER_LISTEN="127.0.0.1:7797" BEST_PEER_ENDPOINT="http://127.0.0.1:7797"
export BEST_PEER_RUNTIME="${BEST_PEER_RUNTIME:-docker}"
base="$BEST_PEER_ENDPOINT"
say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
j() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
events() {  # correlation id -> the event types and data, one per line, following nextCursor to the end
  local after="" page
  while :; do
    page=$(curl -sf -H "X-Api-Key: $key" "$base/events?correlationId=$1&limit=200${after:+&after=$after}") || return 1
    echo "$page" | python3 -c 'import json,sys; d=json.load(sys.stdin)
for e in d["events"]: print(" ", e["time"][11:19], e["type"], json.dumps(e["data"]))'
    after=$(echo "$page" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("nextCursor") or "")')
    [ -n "$after" ] || break
  done
}
done_types='DeploymentReady DeploymentFailed CommandFailed OutOfMemory DeploymentEnded PromptAnswered PromptFailed'
wait_outcome() {  # correlation id -> the completing event's type, polling the log
  local t
  for _ in $(seq 1 600); do
    t=$(events "$1" | awk '{print $2}' | grep -m1 -E "^($(echo $done_types | tr ' ' '|'))$" || true)
    [ -n "$t" ] && { echo "$t"; return; }
    sleep 3
  done
  echo "timeout"
}

say "best-peer: $("$exe" --version 2>&1)"
"$exe" 2> "$data/peer.log" &
peer=$!
trap 'kill $peer 2>/dev/null; rm -rf "$data"' EXIT
for _ in $(seq 1 30); do curl -sf "$base/.well-known/best" > /dev/null && break; sleep 1; done
if ! kill -0 $peer 2>/dev/null; then say "the peer did not start:"; cat "$data/peer.log"; exit 1; fi

device=$(curl -sf -X POST "$base/auth/device" -d client_id=proof -d connection=gpu-host -d agent_label="the GPU host proof")
user_code=$(echo "$device" | j 'd["user_code"]')
device_code=$(echo "$device" | j 'd["device_code"]')
"$exe" approve "$user_code" > /dev/null
token=$(curl -sf -X POST "$base/auth/token" -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d "device_code=$device_code" -d client_id=proof)
key=$(echo "$token" | j 'd["access_token"]')
say "signed in as gpu-host (the key stays in this shell)"

say "get-hardware-state:"
hw=$(curl -sf -H "X-Api-Key: $key" "$base/queries/get-hardware-state")
echo "$hw" | python3 -c 'import json,sys; d=json.load(sys.stdin)
print("  driver", d["driver"])
for x in d["devices"]:
    m=x["memory"]; print("  ", x["id"], "|", x["name"], "|", [c.get("api")+(" "+c["version"] if c.get("version") else "") for c in x["compute"]], "| free %.1f of %.1f GB" % (m["free_bytes"]/2**30, m["total_bytes"]/2**30), "| temp", x["temperature_c"], "C | power", x["power_w"], "W | util", x["utilisation_pct"], "%")'
card=$(echo "$hw" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next((x["id"] for x in d["devices"] if any(c.get("api")=="cuda" for c in x["compute"])), ""))')
[ -n "$card" ] || { say "no device offers cuda: nothing to deploy on"; exit 1; }

say "deploy $model with ollama on $card, 4 GB:"
envelope=$(python3 -c 'import json,sys,datetime; print(json.dumps({"specversion":"1.0","id":"gpu-proof-deploy","source":"https://proof.local/agent","type":"DeployModel","datacontenttype":"application/json","dataschema":sys.argv[1]+"/commands/deploy-model/1.0","time":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"data":{"model":sys.argv[2],"engine":"ollama","memory_bytes":4*2**30,"device":sys.argv[3]}}))' "$base" "$model" "$card")
accepted=$(curl -s -w '\n%{http_code}' -H "X-Api-Key: $key" -H "Content-Type: application/cloudevents+json" -d "$envelope" "$base/commands")
status=$(echo "$accepted" | tail -1)
say "  $status $(echo "$accepted" | head -1)"
# A refusal is the outcome: it names the field and the fix, and no event follows.
[ "$status" = 201 ] || { say "the deploy was refused; that is the proof's result on this host"; say "get-workloads: $(curl -sf -H "X-Api-Key: $key" "$base/queries/get-workloads")"; exit 1; }
outcome=$(wait_outcome gpu-proof-deploy)
events gpu-proof-deploy | grep -v -E ' (ImagePulling|WeightsLoading) ' ; say "  progress events: $(events gpu-proof-deploy | grep -c -E ' (ImagePulling|WeightsLoading) ')"
say "  outcome: $outcome"
if [ "$outcome" = DeploymentReady ]; then
  ready=$(events gpu-proof-deploy | grep ' DeploymentReady ' | sed 's/^.*DeploymentReady //')
  dep=$(echo "$ready" | j 'd["deployment"]')
  say "get-hardware-state while it runs (the card's free memory should have dropped):"
  curl -sf -H "X-Api-Key: $key" "$base/queries/get-hardware-state" | python3 -c 'import json,sys; d=json.load(sys.stdin)
for x in d["devices"]:
    if x["id"]==sys.argv[1]: m=x["memory"]; print("  ", x["id"], "free %.1f of %.1f GB, util" % (m["free_bytes"]/2**30, m["total_bytes"]/2**30), x["utilisation_pct"], "%")' "$card"
  say "prompt $dep with the prompt command (the one way to the model):"
  p=$(python3 -c 'import json,sys,datetime; print(json.dumps({"specversion":"1.0","id":"gpu-proof-prompt","source":"https://proof.local/agent","type":"Prompt","datacontenttype":"application/json","dataschema":sys.argv[1]+"/commands/prompt/1.0","time":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"data":{"deployment":sys.argv[2],"messages":[{"role":"user","content":"Answer with one word: what is the capital of Italy?"}],"max_tokens":20}}))' "$base" "$dep")
  accepted=$(curl -s -w '\n%{http_code}' -H "X-Api-Key: $key" -H "Content-Type: application/cloudevents+json" -d "$p" "$base/commands")
  say "  $(echo "$accepted" | tail -1) $(echo "$accepted" | head -1)"
  say "  outcome: $(wait_outcome gpu-proof-prompt)"
  answered=$(events gpu-proof-prompt | grep ' PromptAnswered ' | sed 's/^.*PromptAnswered //')
  [ -n "$answered" ] && say "  $(echo "$answered" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(repr(d["content"].strip()), "in", d["completion_tokens"], "tokens, finish", d["finish"])' 2>/dev/null || echo "$answered")"
  say "container's view of the card: $(docker exec "$(docker ps -q --filter label=best-peer | head -1)" nvidia-smi --query-gpu=name,memory.used --format=csv,noheader 2>&1 | head -1)"
  say "undeploy:"
  u=$(python3 -c 'import json,sys,datetime; print(json.dumps({"specversion":"1.0","id":"gpu-proof-undeploy","source":"https://proof.local/agent","type":"UndeployModel","datacontenttype":"application/json","dataschema":sys.argv[1]+"/commands/undeploy-model/1.0","time":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"data":{"deployment":sys.argv[2]}}))' "$base" "$dep")
  curl -s -H "X-Api-Key: $key" -H "Content-Type: application/cloudevents+json" -d "$u" "$base/commands" > /dev/null
  sleep 5; events gpu-proof-undeploy
fi
say "get-workloads: $(curl -sf -H "X-Api-Key: $key" "$base/queries/get-workloads")"
say "peer log:"; sed 's/^/  /' "$data/peer.log" | tail -20
say "PROOF DONE: paste everything above on the slice's issue"
