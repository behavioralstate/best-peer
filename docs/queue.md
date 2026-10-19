# The queue, against the serverless GPU platforms

What a workspace's cloud does with a `run-job` order, set beside what Verda's batch jobs and RunPod Serverless
document for theirs, so the gap is written down rather than guessed. The README's Deploy section is how the queue
behaves; this page is only the comparison. Where a gap has an issue, it is named; open work lives there, not here.

## What the queue does

- An order is taken when a device of the cloud's members could ever hold it, and refused at once when none could.
  It waits only for room, and is placed first come, first served per cloud; an order that does not fit yet holds
  back none that does.
- Its facts, under the caller's correlation id: `JobQueued` (the order whole, `waiting` when it waits), `JobPlaced`
  (the member peer), then the member's `ImagePulling`, `ImagePulled`, `JobStarted` (naming the order), and
  `JobFinished` with the exit code, `JobFailed` or `JobStopped`.
- `queue_seconds` bounds the wait, a day when the order names none, and `deadline_seconds` the run, both from the
  facts' own times.
- `stop-job` ends a waiting order, or a running job by its job id or its order's.
- A member lost under an order queues it again once (`attempt: 2`), then fails it.
- The queue is folded from those facts, so it survives a restart of the door, and a job that ends after one is told
  with its exit code.

## Beside the platforms

| What they offer | Verda batch jobs | RunPod Serverless | best-peer's cloud |
|---|---|---|---|
| Submit, asynchronously, and get an id | yes | `/run` | `run-job`, `JobQueued`'s `job` |
| A synchronous call that waits for the result | no | `/runsync` | no: a command's outcome is always an event |
| Status of a job | a status path | `/status` | the stream, `get-workloads` (`queued`, `jobs`) |
| The job's output | a result path | `output` in `/status`, kept for a while | no: the exit code only; inputs and outputs are behavioralstate/spec#66 |
| A bound on the run | `deadline_seconds` | `executionTimeout` | `deadline_seconds` |
| A bound on the wait | `queue_message_ttl_seconds` | `ttl`, from submission, covering the wait and the run | `queue_seconds`, the wait alone, a day by default |
| Cancel a queued or running job | not documented | `/cancel` | `stop-job` |
| Retry a failed job under the same id | not documented | `/retry` | no: order it again |
| Clear the queue | not documented | `/purge-queue` | no: `stop-job` each order |
| Queue and worker counts | not documented | `/health` | `get-workloads` and `get-clouds` |
| Scale to zero, a maximum of workers | scale to zero, `max_replica_count` | min and max workers, idle timeout | machines the owners hold; rented ones are behavioralstate/spec#56 |
| GPU types in order of preference | the deployment's | a list per endpoint | the menu's sizes, behavioralstate/spec#63, placed across sources by behavioralstate/spec#60 |
| A lost worker | a job is not restarted on its own | the platform's | queued again once, then failed |

## Where the docs are

- Verda batch jobs: <https://docs.verda.com/containers/batch-jobs/>
- RunPod Serverless job operations: <https://docs.runpod.io/serverless/endpoints/operations>

"Not documented" means the pages above say nothing about it, not that the platform lacks it.
