# Sharing a card

Whether a consumer card with no MIG can be split between jobs, and held to the split: the questions of
[behavioralstate/spec#65](https://github.com/behavioralstate/spec/issues/65), answered with best-peer's container
runtime (Docker and the NVIDIA container toolkit). The menu's sizes
([spec#63](https://github.com/behavioralstate/spec/issues/63)) and the fair bill's factor
([spec#61](https://github.com/behavioralstate/spec/issues/61)) are to follow what this page says the card can hold.

**Where it ran:** an NVIDIA GeForce GTX 1660 SUPER (Turing, compute capability 7.5, 6 GB, no MIG), driver 575.51.03,
Docker 28.1.1 with overlay2 on an ext file system (Docker reports `extfs`), in a VM rented on Vast.ai on 2026-10-20.
The owner's call was that a cheaper consumer card answers the questions the 5090 was named for. The 5090 (Blackwell,
32 GB) may give other numbers: the same script answers it in ten minutes before its fractions are sold.

**How:** [sharing/spike.sh](sharing/spike.sh) runs [sharing/probe.cu](sharing/probe.cu) in containers on the one
card. The probe allocates and touches memory in steps (`alloc`), runs a compute-bound kernel back to back and counts
launches a second (`burn`: 4096 blocks of 256 threads, 2000 multiply-adds each), or writes through a bad pointer
(`fault`). The figures below are from that run.

## Device memory: held per job under MPS, and only there

- **Without MPS nothing holds a container to a share.** One container took 5,632 of the 5,749 MiB the card offers. A
  second, started while another held 3 GiB, saw 2,541 MiB free and failed after 2,048.
- **Under MPS, `CUDA_MPS_PINNED_DEVICE_MEM_LIMIT` holds.** A container limited to `0=1G` saw 962 MiB free and failed
  at 768 MiB. Beside it at the same time, one with no limit took 4,608 MiB, untouched. One limited to `0=2G` saw
  1,986 MiB free and failed at 1,792. About 60 MiB of each limit goes to the job's own CUDA context, as the free
  memory each saw says; the failures fall lower because the probe allocates in steps of 256 MiB.
- **The failure is the job's own.** It is CUDA's ordinary `out of memory` inside the job (`alloc failed at 768 MiB:
  out of memory`), the same as on a full card. Nothing outside the job sees it: the job ends or carries on as its code
  decides, and the peer learns only its exit code. A `JobFailed` can name the slice the size reserved, not the
  allocation that failed.

## Compute: a ceiling fixed at start, not a guarantee

- **`CUDA_MPS_ACTIVE_THREAD_PERCENTAGE` caps a job even when it is alone.** Alone at 100 the probe ran 1,245 launches
  a second, at 50 it ran 568 (46%), at 25 it ran 229 (18%). Every share measured matches whole pairs of the card's 22
  multiprocessors, rounded down: 10, 4, 6 and 14 of 22 for 50, 25, 30 and 70. Whether the pairs are the card's or
  MPS's was not tested. Single multiprocessors would have given 50% and 23% for 50 and 25.
- **Two at once take what their caps give.** At 30 and 70 they ran 339 and 786 (27% and 63% of one alone); at 50 and
  50, 552 each.
- **A share is fixed for the life of the job.** `set_active_thread_percentage` on the MPS server, sent 12 s into a job
  started at 50, left it at 564 launches a second to its end. The change applies to jobs that start after it, and caps
  them even when they ask for more: a job that asked for 50 after the server was set to 20 ran at 227, as did one that
  asked for nothing.
- **A job joining or leaving does not move the others.** A job at 50 ran at 564 a second throughout while another
  joined and left beside it, their caps together under 100.
- **With no percentage, MPS divided the card evenly** between identical jobs computing: 605 each for two, 400 each
  for three. A job alone gets all of it. Jobs asking for different amounts were not measured.

So the percentage is a ceiling. A job capped at 50 does not use the other half when the card is idle, which is what
decision 6 of [spec#64](https://github.com/behavioralstate/spec/issues/64) asks: a guaranteed share, and idle compute
above it.

## Without MPS: time-slicing

Two identical containers computing at once ran 596 launches a second each, three ran 392 each: equal parts. Whether
containers asking for different amounts get equal parts, or what each asks for, was not measured: every container ran
the same kernel.

## The cost of sharing

What the card did in total, against one job alone (launches a second, the compute-bound kernel above):

| | alone | two at once | three at once |
|---|---|---|---|
| Time-slicing, no MPS | 1,259 | 1,191 (94.6%) | 1,175 (93.3%) |
| MPS, no percentage | 1,245 | 1,210 (97.3%) | 1,202 (96.6%) |
| MPS, 50 and 50 | | 1,105 (88.8%) | |
| MPS, 30 and 70 | | 1,125 (90.4%) | |

Capped shares cost more than uncapped ones: a cap is rounded down to whole pairs of multiprocessors, and what it
rounds away is left idle (50 and 50 used 20 of the 22).
Memory-bound work and real engines were not measured.

## Isolation

- **Without MPS, a fault stays in its job.** An illegal memory access in one container ended that container alone;
  the one computing beside it ran on at full rate.
- **Under MPS, a fault ends its neighbours' work.** The same fault made the job computing beside it fail with the same
  error after 1,020 launches. The MPS server took new jobs afterwards.
- **A job sees how much memory the others hold**, with MPS and without: its free memory is the card's less theirs.
  `nvidia-smi` in a container lists the other containers' processes, by their host process id, with their memory:
  `5100, 3138 MiB` for one holding 3 GiB.
- **Exclusive-process mode did not keep a container off the card.** A container started without the MPS pipe, at a
  moment when no MPS job was running, made a context of its own on the card. Whether one is refused while an MPS job
  runs was not tried. Either way, the peer has to start every job on a shared card through MPS, with its limits,
  itself.

## Disk

- **Docker's own cap needs XFS.** On the host's overlay2 over an ext file system, `--storage-opt size=1G` was refused:
  "supported only for overlay over xfs with 'pquota' mount option".
- **On XFS with project quotas it holds.** With Docker's data root moved to an XFS file system mounted with `pquota`,
  a container started with `--storage-opt size=1G` that wrote 2,000 MiB stopped at 1,024 MiB, its root full.
- **A size-limited volume per job holds too.** A 1 GiB ext4 file system on a loop device, mounted into the container,
  stopped a 2,000 MiB write at 957 MiB.

## What it means for the menu

- **Memory slices can be sold on a consumer card with no MIG,** where the peer runs MPS and starts each job on the
  card with its pinned limit: `slicing: mps`. Each slice loses about 60 MiB to the job's context.
- **Compute cannot be sold as decision 6 has it** with MPS on this card. There are two ways to sell it instead, for
  the owner to choose, and #63's sizes and #61's factor follow the choice:
  1. **A share as a ceiling.** Each size has a percentage, set when its job starts. The job gets that percentage
     rounded down to the steps observed here (whole pairs of multiprocessors, cause untested), alone or not, never the
     idle compute above it: on this card 50 gave 46% of one job alone, and 25 gave 18%. What a job is given never
     changes, so its factor is 1 when the size's share is that measured fraction, not the nominal percentage. A size
     priced at 25% would get 18% of the card.
  2. **No percentage.** Identical jobs on a card divided it evenly while they computed, and a job alone has all of it.
     If unequal jobs divide it evenly too, which was not measured, the factor of decision 7 is the share a job had,
     one over the number of jobs computing on the card. It is known from the allocation the peer made, and it changes
     as jobs join and leave.
- **Strangers do not share a card under MPS.** A fault in one job ends its neighbours' work, and each job sees the
  others' memory. Decision 8's line holds: a card shared under MPS is shared by one client's jobs, or by pilot clients
  who accept it in writing. Other clients get whole cards.
- **A size's disk floor can be held** by Docker's cap, with its data root on XFS with project quotas, or by a
  size-limited volume per job.
- **What the machine needs** for a shared card:
  - the MPS control daemon on the host;
  - each job on the card given the daemon's pipe directory (mounted, with `--ipc=host` and
    `CUDA_MPS_PIPE_DIRECTORY`) and its limits;
  - the card in exclusive-process mode;
  - for disk caps, Docker's data root on XFS mounted with `pquota`.

## Not answered here

- **The 5090's own figures.** The behaviours above (a share fixed at start, a fault shared under MPS, a pinned limit
  held) belong to MPS rather than to Turing, and are expected to hold on Blackwell, but that is unverified, and the
  step a share is rounded to may differ there.
- **Inference engines under MPS.** Ollama and vLLM keep their own memory pools and were not run with a pinned limit.
