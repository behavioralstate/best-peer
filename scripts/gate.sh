#!/usr/bin/env bash
# The local proof of SDLC.md section 3, on Linux and macOS: fmt, clippy with warnings as errors, the tests, a release
# build, then best-validate against the built peer on the fakes, anonymous, signed in over https through the real
# device flow and `best-peer approve`, and on a workspace's cloud over two member peers. The last line is GATE GREEN
# or GATE RED, and nothing else is a pass. CI runs this same script, so the proof on a maintainer's machine and the
# check on the pull request are one thing. Windows runs scripts/gate.ps1, which reads the validator's version below.
#
#   scripts/gate.sh [fmt|clippy|test|build|validate|all]      default: all
#
# Needs cargo, node (npx), curl and python3. The peers listen on 127.0.0.1:7791 to 7796, away from a peer already
# serving on 7777, and leave nothing behind: each lane's data folders are temporary and its peers are stopped on exit.
set -uo pipefail
BEST_VALIDATE_VERSION=0.4.2

cd "$(dirname "$0")/.."
what="${1:-all}"
case "$what" in
  fmt|clippy|test|build|validate|all) ;;
  *) echo "scripts/gate.sh: unknown step '$what'; one of fmt, clippy, test, build, validate, all"; echo "GATE RED"; exit 1 ;;
esac
bin="target/release/best-peer"
failed=0
step() {  # name command...: runs the command, keeps the verdict, never stops the script. The command is run on its
  # own, never as the test of an `if`: bash ignores `set -e` inside anything that runs as a condition, lanes included.
  local name="$1"; shift
  echo "=== $name"
  "$@"
  local rc=$?
  if [ "$rc" -ne 0 ]; then echo "FAILED: $name"; failed=1; fi
}
wants() { [[ "$what" == all || "$what" == "$1" ]]; }

if wants fmt; then step "fmt" cargo fmt --all --check; fi
if wants clippy; then step "clippy" cargo clippy --workspace --all-targets -- -D warnings; fi
if wants test; then step "test" cargo test --workspace; fi
if wants build || wants validate; then step "release build" cargo build --release -p best-peer; fi

# Each lane is a subshell with its own temporary folders and its own peers, stopped whatever the outcome.
export BEST_PEER_RUNTIME=fake BEST_PEER_GPU=none
validate() { npx -y "@behavioralstate/best-validate@$BEST_VALIDATE_VERSION" "$@"; }
wait_up() {  # pid url [curl options]: the peer this lane started answers its manifest within thirty seconds, or the
  # lane fails. The process is checked before the port is trusted: a peer left on the port by an earlier run would
  # answer in place of the one that could not bind, and the gate would validate the wrong binary.
  local pid="$1" url="$2"; shift 2
  for _ in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || { echo "the peer for $url exited before it answered"; return 1; }
    curl -sf "$@" "$url" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "the peer at $url did not answer"; return 1
}
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }

lane_anonymous() (
  set -euo pipefail
  data="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$data"' EXIT
  BEST_PEER_DATA="$data" BEST_PEER_LISTEN=127.0.0.1:7791 BEST_PEER_ENDPOINT=http://127.0.0.1:7791 "$bin" &
  wait_up $! http://127.0.0.1:7791/.well-known/best
  validate http://127.0.0.1:7791
)

# As an admitted agent, over https: a peer with an https endpoint and no certificate given makes its own, and every
# call is pinned to that file (curl --cacert, the validator through NODE_EXTRA_CA_CERTS): the device flow, approval
# with this machine's admin token through the real `best-peer approve`, the credential redeemed, and the validator
# probing every active capability with it. Nothing here prints the credential.
lane_signed_in() (
  set -euo pipefail
  data="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$data"' EXIT
  base=https://127.0.0.1:7792
  cert="$data/tls/cert.pem"
  BEST_PEER_DATA="$data" BEST_PEER_LISTEN=127.0.0.1:7792 BEST_PEER_ENDPOINT="$base" "$bin" &
  wait_up $! "$base/.well-known/best" --cacert "$cert"
  device=$(curl -sf --cacert "$cert" -X POST "$base/auth/device" -d client_id=gate -d connection=gate-peer -d "agent_label=the gate")
  user_code=$(echo "$device" | json 'd["user_code"]')
  device_code=$(echo "$device" | json 'd["device_code"]')
  echo "$device" | python3 -c 'import json,sys; assert json.load(sys.stdin)["verification_uri"].startswith("https://"), "the verification URI is not https"'
  BEST_PEER_DATA="$data" "$bin" approve "$user_code"
  token=$(curl -sf --cacert "$cert" -X POST "$base/auth/token" -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d "device_code=$device_code" -d client_id=gate)
  key=$(echo "$token" | json 'd["access_token"]')
  echo "$token" | python3 -c 'import json,sys; t=json.load(sys.stdin); assert t["name"]=="gate-peer" and t["auth_header"]=="X-Api-Key" and t["note"].startswith("The credential is a secret."), "the token answer lacks a BEST member"'
  NODE_EXTRA_CA_CERTS="$cert" validate "$base" --api-key "$key" --auth-type apikey --auth-header X-Api-Key --probe-registration
)

# A workspace and a cloud: the same binary as the door, over two member peers on the fakes. The agent creates the
# workspace and configures the cloud through the surface, each member admits the cloud through the real
# `best-peer approve` with the code the door logs, and the validator probes the root and the workspace's own
# manifest (--tenant), anonymous and signed in. Then BEST_PEER_MEMBERS is refused at start, with the fix.
lane_cloud() (
  set -euo pipefail
  root="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$root"' EXIT
  mkdir -p "$root/a" "$root/b" "$root/door" "$root/old"
  BEST_PEER_DATA="$root/a" BEST_PEER_LISTEN=127.0.0.1:7793 BEST_PEER_ENDPOINT=http://127.0.0.1:7793 "$bin" &
  pid_a=$!
  BEST_PEER_DATA="$root/b" BEST_PEER_LISTEN=127.0.0.1:7794 BEST_PEER_ENDPOINT=http://127.0.0.1:7794 "$bin" &
  pid_b=$!
  BEST_PEER_DATA="$root/door" BEST_PEER_LISTEN=127.0.0.1:7795 BEST_PEER_ENDPOINT=http://127.0.0.1:7795 "$bin" > "$root/door/log" 2>&1 &
  pid_door=$!
  wait_up "$pid_a" http://127.0.0.1:7793/.well-known/best
  wait_up "$pid_b" http://127.0.0.1:7794/.well-known/best
  base=http://127.0.0.1:7795
  wait_up "$pid_door" "$base/.well-known/best"
  curl -sf "$base/.well-known/best" | python3 -c 'import json,sys; m=json.load(sys.stdin)["best"]; assert m["tenants"]["manifest"].endswith("/.well-known/best/{tenantId}"), m'
  device=$(curl -sf -X POST "$base/auth/device" -d client_id=gate -d connection=gate-door -d "agent_label=the gate")
  user_code=$(echo "$device" | json 'd["user_code"]')
  device_code=$(echo "$device" | json 'd["device_code"]')
  BEST_PEER_DATA="$root/door" "$bin" approve "$user_code"
  token=$(curl -sf -X POST "$base/auth/token" -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d "device_code=$device_code" -d client_id=gate)
  key=$(echo "$token" | json 'd["access_token"]')
  command() {  # base id type schema data -> POST /commands, fails on anything but 201
    local body
    body=$(python3 -c 'import json,sys,datetime; print(json.dumps({"specversion":"1.0","id":sys.argv[2],"source":"https://gate.test/agent","type":sys.argv[3],"datacontenttype":"application/json","dataschema":sys.argv[1]+"/commands/"+sys.argv[4]+"/1.0","time":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"data":json.loads(sys.argv[5])}))' "$@")
    curl -sf -H "X-Api-Key: $key" -H "Content-Type: application/cloudevents+json" -d "$body" "$1/commands" >/dev/null
  }
  command "$base" gate-ws CreateWorkspace create-workspace '{"name":"Gate"}'
  ws=""
  for _ in $(seq 1 40); do
    ws=$(curl -sf -H "X-Api-Key: $key" "$base/queries/get-workspaces" | json 'd["workspaces"][0]["workspace"] if d["workspaces"] else ""')
    [ -n "$ws" ] && break; sleep 0.5
  done
  [ -n "$ws" ] || { echo "no workspace after create-workspace:"; cat "$root/door/log"; exit 1; }
  tenant="$base/workspaces/$ws"
  command "$tenant" gate-cloud ConfigureCloud configure-cloud '{"cloud":"lab","members":[{"peer":"a","endpoint":"http://127.0.0.1:7793"},{"peer":"b","endpoint":"http://127.0.0.1:7794"}]}'
  for m in a b; do
    for _ in $(seq 1 40); do grep -q "on $m, run on that machine" "$root/door/log" && break; sleep 0.5; done
    code=$(grep -o "on $m, run on that machine: best-peer approve [A-Z0-9-]*" "$root/door/log" | head -1 | awk '{print $NF}')
    [ -n "$code" ] || { echo "the cloud asked $m for no code:"; cat "$root/door/log"; exit 1; }
    BEST_PEER_DATA="$root/$m" "$bin" approve "$code"
  done
  up=0
  for _ in $(seq 1 60); do
    up=$(curl -sf -H "X-Api-Key: $key" "$tenant/queries/get-clouds" | json 'sum(1 for p in d["clouds"][0]["peers"] if p["state"]=="up")')
    [ "$up" = 2 ] && break; sleep 0.5
  done
  [ "$up" = 2 ] || { echo "the cloud sees $up of 2 members up"; cat "$root/door/log"; exit 1; }
  curl -sf -H "X-Api-Key: $key" "$tenant/queries/get-hardware-state" | python3 -c 'import json,sys; ids=[d["id"] for d in json.load(sys.stdin)["devices"]]; assert ids==["lab/a/cpu-0","lab/b/cpu-0"], ids'
  validate "$base" --tenant "$ws"
  validate "$base" --tenant "$ws" --api-key "$key" --auth-type apikey --auth-header X-Api-Key --probe-registration
  echo "=== BEST_PEER_MEMBERS is refused with the fix"
  # In the background with a bound: a peer that wrongly accepts the variable would serve for ever in the foreground,
  # and the gate would hang instead of going red.
  BEST_PEER_DATA="$root/old" BEST_PEER_LISTEN=127.0.0.1:7796 BEST_PEER_MEMBERS=a=http://127.0.0.1:7793 "$bin" 2> "$root/old/refused" &
  pid_old=$!
  for _ in $(seq 1 20); do kill -0 "$pid_old" 2>/dev/null || break; sleep 0.5; done
  if kill -0 "$pid_old" 2>/dev/null; then echo "BEST_PEER_MEMBERS was accepted: the peer is still serving"; exit 1; fi
  if wait "$pid_old"; then echo "BEST_PEER_MEMBERS was accepted: the peer exited 0"; exit 1; fi
  grep -q "configure-cloud" "$root/old/refused" || { echo "the refusal does not name configure-cloud:"; cat "$root/old/refused"; exit 1; }
)

if wants validate; then
  step "validate, anonymous" lane_anonymous
  step "validate, signed in over https, with the registration probe" lane_signed_in
  step "validate, a workspace with a cloud over two members" lane_cloud
fi

if [ "$failed" -ne 0 ]; then echo "GATE RED"; exit 1; else echo "GATE GREEN"; fi
