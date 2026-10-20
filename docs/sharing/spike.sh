#!/usr/bin/env bash
# behavioralstate/spec#65 on a consumer card with no MIG: can it be split between containers, and held to the split?
# Device memory and compute under MPS, time-slicing without it, the cost of sharing, isolation, and a disk cap.
# Each step prints what it ran and what came back; nothing is judged here, docs/sharing.md reads it.
#
# Run as root on a host with one NVIDIA card, Docker and the NVIDIA container toolkit, from this folder (or with
# SPIKE_DIR set to it): `bash spike.sh | tee spike.log`. It takes about ten minutes. Steps D to I change the card's
# compute mode and start an MPS daemon, and step L moves Docker's data root for a moment; each puts things back. The
# probe is built for sm_75 with PTX, so a newer card runs it through the driver's JIT.
set -uo pipefail
say() { printf '\n[%s] == %s\n' "$(date -u +%H:%M:%S)" "$*"; }
note() { printf '  -> %s\n' "$*"; }
W=${SPIKE_DIR:-$(cd "$(dirname "$0")" && pwd)}
IMG=nvidia/cuda:12.4.1-base-ubuntu22.04
DEVEL=nvidia/cuda:12.4.1-devel-ubuntu22.04
UUID=$(nvidia-smi --query-gpu=uuid --format=csv,noheader | head -1)
# More than the card holds, so an allocation without a limit ends where the card does, whatever its size.
PAST=$(( $(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -1) + 1024 ))
GPU=(--gpus "device=$UUID")
PIPE=/tmp/nvidia-mps
MPS=(--ipc=host -v "$PIPE:$PIPE" -e "CUDA_MPS_PIPE_DIRECTORY=$PIPE")
# probe name [docker args...] -- probe args: one container, named, its output prefixed with the name.
probe() {
  local name=$1; shift; local args=()
  while [ "$1" != "--" ]; do args+=("$1"); shift; done; shift
  docker run --rm --name "$name" "${GPU[@]}" -v "$W:/w:ro" "${args[@]}" "$IMG" /w/probe "$@" 2>&1 | sed "s/^/  [$name] /"
  return "${PIPESTATUS[0]}"
}

say "the card"
nvidia-smi --query-gpu=name,uuid,memory.total,compute_cap,driver_version,compute_mode --format=csv
nvidia-smi -q | grep -iE 'MIG Mode|Current *:' | head -3
docker info --format 'docker {{.ServerVersion}}, storage {{.Driver}} on {{index .DriverStatus 0}}'

say "build the probe (nvcc in $DEVEL, run in $IMG)"
docker pull -q "$IMG" > /dev/null; docker pull -q "$DEVEL" > /dev/null
docker run --rm -v "$W:/w" -w /w "$DEVEL" nvcc -O2 -arch=sm_75 -o probe probe.cu && ls -l "$W/probe"

# ----- without MPS: time-slicing ------------------------------------------------------------------------------------
say "A. without MPS: one container alone, then two and three at once (burn 30 s each)"
probe solo -- burn 30 | tail -1
for n in 2 3; do
  note "$n at once"
  for i in $(seq 1 "$n"); do probe "ts$n-$i" -- burn 30 | tail -1 & done; wait
done

say "B. without MPS: nothing holds a container to a share of memory"
probe greedy -- alloc 512 "$PAST" 5 | grep -E 'failed|holding'
note "while one holds 3 GiB, what a second sees and can take"
probe holder -- alloc 512 3072 25 | grep -E 'holding|done' &
sleep 8
probe second -- alloc 512 "$PAST" 1 | grep -E 'seen|failed|holding'
docker run --rm "${GPU[@]}" "$IMG" nvidia-smi --query-compute-apps=pid,used_memory --format=csv | sed 's/^/  [nvidia-smi in a third] /'
wait

say "C. without MPS: a fault in one container, beside one that computes"
probe calm -- burn 20 | tail -1 &
sleep 5; probe faulty -- fault; note "faulty exited $?"
wait

# ----- MPS ----------------------------------------------------------------------------------------------------------
say "D. MPS: the control daemon on the host, the card in exclusive-process mode"
nvidia-smi -i "$UUID" -c EXCLUSIVE_PROCESS
mkdir -p "$PIPE" /tmp/nvidia-mps-log
CUDA_MPS_PIPE_DIRECTORY=$PIPE CUDA_MPS_LOG_DIRECTORY=/tmp/nvidia-mps-log nvidia-cuda-mps-control -d && note "daemon started"
probe mps-info "${MPS[@]}" -- info
SERVER=$(echo get_server_list | CUDA_MPS_PIPE_DIRECTORY=$PIPE nvidia-cuda-mps-control); note "server: $SERVER"
note "a container without the pipe, while MPS runs:"; probe no-pipe -- info

say "E. MPS: device memory held per container (CUDA_MPS_PINNED_DEVICE_MEM_LIMIT)"
probe lim1g "${MPS[@]}" -e CUDA_MPS_PINNED_DEVICE_MEM_LIMIT=0=1G -- alloc 256 4000 20 &
sleep 3
probe lim2g "${MPS[@]}" -e CUDA_MPS_PINNED_DEVICE_MEM_LIMIT=0=2G -- alloc 256 2048 5
wait
note "one with no limit beside one held to 1 GiB"
probe lim1g-b "${MPS[@]}" -e CUDA_MPS_PINNED_DEVICE_MEM_LIMIT=0=1G -- alloc 256 1024 15 | grep -E 'seen|holding|failed' &
sleep 3
probe nolimit "${MPS[@]}" -- alloc 512 "$PAST" 1 | grep -E 'seen|failed|holding'
wait

say "F. MPS: a share of compute per container (CUDA_MPS_ACTIVE_THREAD_PERCENTAGE)"
probe p100 "${MPS[@]}" -- burn 20 | tail -1
probe p50 "${MPS[@]}" -e CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=50 -- burn 20 | tail -1
probe p25 "${MPS[@]}" -e CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=25 -- burn 20 | tail -1
note "30 and 70 at once"
probe at30 "${MPS[@]}" -e CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=30 -- burn 30 | tail -1 &
probe at70 "${MPS[@]}" -e CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=70 -- burn 30 | tail -1 &
wait
note "50 and 50 at once"
probe h1 "${MPS[@]}" -e CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=50 -- burn 30 | tail -1 &
probe h2 "${MPS[@]}" -e CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=50 -- burn 30 | tail -1 &
wait
note "two and three at once, no percentage"
for n in 2 3; do
  for i in $(seq 1 "$n"); do probe "mps$n-$i" "${MPS[@]}" -- burn 30 | tail -1 & done; wait
done

say "G. MPS: a share changed while a job runs, and a job joining and leaving"
probe long "${MPS[@]}" -e CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=50 -- burn 45 &
sleep 12
SERVER=$(echo get_server_list | CUDA_MPS_PIPE_DIRECTORY=$PIPE nvidia-cuda-mps-control | head -1)
note "set_active_thread_percentage $SERVER 20 at 12 s: $(echo "set_active_thread_percentage $SERVER 20" | CUDA_MPS_PIPE_DIRECTORY=$PIPE nvidia-cuda-mps-control)"
sleep 3
note "a job joins at 15 s with 50, leaves at 30 s"
probe joiner "${MPS[@]}" -e CUDA_MPS_ACTIVE_THREAD_PERCENTAGE=50 -- burn 15
note "a new client after the server's change, no percentage of its own:"
probe after "${MPS[@]}" -- burn 10 | tail -1
wait

say "H. MPS: a fault in one client, beside one that computes"
probe calm-mps "${MPS[@]}" -- burn 20 | tail -1 &
sleep 5; probe faulty-mps "${MPS[@]}" -- fault; note "faulty exited $?"
wait
note "a new client after the fault:"; probe after-fault "${MPS[@]}" -- info
note "what one client sees of another's memory:"
probe seen-holder "${MPS[@]}" -- alloc 512 2048 12 | grep holding &
sleep 5; probe seen-other "${MPS[@]}" -- info; wait

say "I. MPS stopped, the card back to its default mode"
echo quit | CUDA_MPS_PIPE_DIRECTORY=$PIPE nvidia-cuda-mps-control; sleep 2
nvidia-smi -i "$UUID" -c DEFAULT

# ----- disk ---------------------------------------------------------------------------------------------------------
say "J. disk: Docker's own cap on a container's writable layer"
docker run --rm --storage-opt size=1G busybox true 2>&1 | sed 's/^/  /'; note "exit ${PIPESTATUS[0]}"

say "K. disk: a size-limited volume per job (a 1 GiB ext4 file system on a loop device)"
truncate -s 1G /root/job.img && mkfs.ext4 -q -F /root/job.img && mkdir -p /mnt/job && mount -o loop /root/job.img /mnt/job
docker run --rm -v /mnt/job:/out busybox sh -c 'dd if=/dev/zero of=/out/big bs=1M count=2000 2>&1 | tail -2; df -h /out | tail -1'
umount /mnt/job; rm -f /root/job.img

say "L. disk: overlay2 on XFS with project quotas (Docker moved to it for this step)"
apt-get install -y -qq xfsprogs > /dev/null 2>&1
truncate -s 12G /root/xfs.img && mkfs.xfs -q -f /root/xfs.img && mkdir -p /mnt/xfs && mount -o loop,pquota /root/xfs.img /mnt/xfs
cp /etc/docker/daemon.json /root/daemon.json.bak 2>/dev/null || echo '{}' > /root/daemon.json.bak
python3 -c 'import json; d=json.load(open("/root/daemon.json.bak")); d["data-root"]="/mnt/xfs/docker"; json.dump(d, open("/etc/docker/daemon.json","w"))'
systemctl restart docker && docker info --format '  storage {{.Driver}} on {{index .DriverStatus 0}}, root {{.DockerRootDir}}'
docker run --rm --storage-opt size=1G busybox sh -c 'dd if=/dev/zero of=/big bs=1M count=2000 2>&1 | tail -2; df -h / | tail -1'
cp /root/daemon.json.bak /etc/docker/daemon.json && systemctl restart docker && umount /mnt/xfs && rm -f /root/xfs.img
docker info --format '  back to {{.DockerRootDir}}'

say "SPIKE DONE"
