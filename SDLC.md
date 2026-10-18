# How best-peer is built and shipped

> This is the one place the lifecycle of this repository is written down. Open work of any kind (a slice, a bug, a
> decision, a spec gap) is an issue on the Behavioralstate board, never a file: the epic
> [behavioralstate/spec#27](https://github.com/behavioralstate/spec/issues/27) and its sub-issues are the plan.

## 1. Intake

- Work is a slice of the epic, or an issue filed next to it on the same board, with the problem, the outcome from the
  agent's side, numbered decisions, and a "Done when" list. A spec gap met while implementing is an entry on the
  spec follow-ups issue, never a silent patch and never a spec change up front.
- Ambiguity is resolved by reading the spec and the running code, never by guessing.

## 2. Design rules every change is held to

- BEST is the surface: a capability exists only when it has a schema, a catalogue entry and a description an agent
  can act on; a refusal is a 400 that says what to do; sign-in is the spec's. Nothing is invented before the
  implementation proves the spec lacks it.
- Facts are events; an event is versioned, never mutated; a redelivery is idempotent; nothing is clamped silently.
- Low-level dependencies sit behind abstractions this workspace owns (`Gpu`, `Runtime`, `Engine`, later
  `Transport`); tests use the fakes, never the dependency; an adapter is thin and is proven on a host by hand, with the
  proof on the slice's issue. CI runs on the fakes and never needs an engine or a GPU.
- A command the peer cannot honour in its current state is refused at ingest, before it is accepted, with the reason
  and the fix; a command that was accepted ends in a terminal event, never in silence.
- The accelerator abstraction is vendor-neutral: a workload asks for a compute API and memory, never for a vendor.
- BEST carries the whole of it: a prompt is a command and its answer an event, under the holder's correlation and
  scope; the engine's API is the peer's internal matter behind the `Engine` abstraction, and nothing of it is on the
  door. A door never carries a token of another service.
- Instructions and this file state the current rule, not its history; the history is in git.
- The README's "Try it on your machine" is the operator's path, kept true by the change that moves it: a variable, a
  check at start, a command, the sign-in, or what the terminal shows changes that section in the same commit, and a
  release note that says something is now proven or still open changes its last step.

## 3. Build

- Tests first where one applies, against the fakes: the lifecycle, the refusals, the events, the manifest.
- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; then the served
  manifest through `best-validate`, anonymous and then signed in: an agent registered through the device flow,
  admitted with the real `best-peer approve`, and the validator probing every active capability with that credential.
  CI runs the same, and a surface the spec refuses fails the build.

## 4. Ship

- **Every change is a pull request to `main`, the owner's included.** `main` is protected: a pull request with `ci`
  green is the only way onto it, nothing is force-pushed, and the one exception is the release commit below, which
  the owner's bypass of the protection lets through. A piece of work is a branch, and lands as one commit on `main`
  (a squash merge), the subject saying what changed and why, ending with the assistant's attribution line.
- **Three gates, in this order; nothing moves on while one is open.**
  1. **The local proof**, before the branch is pushed: section 3 on the maintainer's machine, every step green (the
     owner wraps them in a script that ends in `GATE GREEN`; any maintainer runs the same commands); a change that
     touches a host is proven on that host by hand, with the proof on the issue.
  2. **CI** on the pull request: section 3 again, on the fakes; a red check blocks the merge.
  3. **The review**: `/best-review` on the branch, the owner-run review of everything the pull request holds that
     `main` does not. Every finding is answered on its thread with a fix and a test, or set aside with its reason;
     nothing is dropped silently. The owner merges.
- **The merge is what runs.** A host run by the owner builds `main` and runs it; the sha is its version.
- **A release is a tag.** `scripts/release.sh <version> -m "<what it is>"` runs only on a clean `main` level with
  origin, so everything it releases has passed the gates; it bumps the one version in `Cargo.toml` (every crate
  inherits it), commits `Release <version>`, which holds nothing but the version and is the one commit that skips the
  gates and goes onto `main` directly, by the owner, tags `v<version>` with the message and pushes both. The `release` workflow refuses a tag that is
  not on `main`, not on a `Release <version>` commit or not equal to `Cargo.toml`, waits for `ci` to pass on that
  commit, runs the checks on the locked tree, builds the binary for Linux x86_64 (glibc 2.35 or newer: the driver's
  library is loaded at run time, which a static binary cannot do), Windows x86_64 and macOS Apple silicon, checks
  each says the version, and publishes each archive twice, byte for byte the same: under its versioned name, for
  pinning, and under a name without the version that `releases/latest/download` resolves, so the README's commands
  name no version; with checksums, a build provenance attestation and notes made from the release commit's message
  and the commits since the previous release. A release is cut when someone other than the owner will run the
  binary, or when a slice's issue says a host needs it; before 1.0 the minor goes up with a capability and the patch
  with a fix. A change to the workflow is tried with its `workflow_dispatch`, which builds and keeps the archives as
  run artifacts and publishes nothing, whatever ref it is started from.

## 5. A change from another maintainer

- **The same pull request, from a branch of this repository**: a maintainer has write access and branches here; one
  without it forks. One per need the implementation proved, held to sections 2, 3 and 4 as any change is. Its
  description names the spec text it satisfies or the entry it adds to the spec follow-ups issue; a behaviour the
  spec does not ask for is that entry first, so the spec and every implementation of it move together, and never a
  surface of this implementation alone.
- **A checkout that runs ahead of `main` on a host is that host's owner's to run**; what the spec promises of it is
  only what `main` proves.

## 6. What we do not do

- No release of a commit the gates have not passed, the release commit itself excepted; no tag made by hand.
- No push to `main` but the release commit; no force-push; no merge with an unanswered review finding or a red check.
- No plan file, no `TODO`, no dated narrative: open work is an issue.
