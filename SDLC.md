# How best-peer is built and shipped

> This is the one place the lifecycle of this repository is written down. Open work of any kind (a slice, a bug, a
> decision, a spec gap) is an issue on the Behavioralstate board, never a file: the epic
> [behavioralstate/spec#27](https://github.com/behavioralstate/spec/issues/27) and its sub-issues are the plan.

## 1. Intake

- Work is a slice of the epic, or an issue filed next to it on the same board, with the problem, the outcome from the
  agent's side, numbered decisions, and a "Done when" list. A spec gap met while implementing is an entry on the
  spec follow-ups issue, never a silent patch and never a spec change up front.
- Ambiguity is resolved by reading the spec and the running code, never by guessing.
- The board's Status says where each issue is:
  - **Backlog** until its first change.
  - **In progress** from the first change, before it is made, until its code is in a release: while the work is
    built, and after it is pushed until the release that carries it.
  - **In review** once its code is in a release, when all that is left is the proof on a host or the owner's
    acceptance.
  - **Done** when the issue closes, every "Done when" ticked. An issue with nothing to prove on a host or for the
    owner to accept closes when its last change is pushed, and goes from In progress to Done.
  - An epic is **Backlog** until any of its issues is In progress, In review or Done, **In progress** from then
    until it closes, and **Done** when it closes, which is when its last issue does. Ready is not a status an epic
    or a slice holds.

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
  admitted with the real `best-peer approve`, and the validator probing every active capability with that credential;
  then a workspace with a cloud over two member peers, validated on the root and the workspace's manifest.
  `scripts/gate.sh all` (`pwsh scripts/gate.ps1 all` on Windows) runs all of it and ends in `GATE GREEN` or
  `GATE RED`; CI runs the same script, and a surface the spec refuses fails the build.

## 4. Ship

- **Every change is made on `main` and pushed there.** A maintainer commits on `main`, one commit per piece of work
  (or a few, when they are told apart better that way), the subject saying what changed and why, ending with the
  assistant's attribution line; the one prefix is `Review:` on a commit that answers the review. No branch and no
  pull request is needed; a contributor without write access sends a pull request (section 5).
- **Two gates before every push, in this order, both mandatory; nothing is pushed while one is open.**
  1. **The local proof**: section 3 on the maintainer's machine, `scripts/gate.sh all` (`pwsh scripts/gate.ps1 all`
     on Windows) ending in `GATE GREEN`; a change that touches a host is proven on that host by hand, with the proof
     on the issue.
  2. **The review**: `/best-review`, run by the author's assistant on what `main` holds that `origin/main` does not.
     It is the repository's own skill (`.claude/skills/best-review`, in every checkout), and it always runs the
     `best-reviewer` skill (`.claude/skills/best-reviewer`): a reviewer that has not seen the conversation, on a
     separate worker with the model that skill pins (Sonnet 5.5, high effort). The author's session verifies each
     finding and fixes it on `main` with a test, in a `Review:` commit whose message names the findings, or sets it
     aside with its reason in that message (an empty commit when no finding changed a file); nothing is dropped
     silently. What a fix changed is reviewed again, and the local gate runs last, on the very head that is pushed.
- **Pull first.** The push lands on top of what others pushed: `git pull --rebase` before the gates, and again before
  the push if `origin/main` moved meanwhile. After a rebase that brought commits in, the local gate runs again on the
  new head, whatever they touched; the review runs again when the rebase changed one's own commits (a conflict
  resolved), and stands otherwise.
- **CI runs on the push**: the same script, on the fakes. A red `main` is fixed before anything else is pushed.
- **What GitHub holds `main` to**: no force-push and no deletion. It requires no pull request and no check, since the
  gates run before the push and CI checks the push; that they ran is each maintainer's word.
- **The push is what runs.** A host run by the owner builds `main` and runs it; the sha is its version.
- **A release is a tag.** `scripts/release.sh <version> -m "<what it is>"` runs only on a clean `main` level with
  origin, so everything it releases has passed the gates; it bumps the one version in `Cargo.toml` (every crate
  inherits it), commits `Release <version>`, which holds nothing but the version and is the one commit that skips the
  gates, tags `v<version>` with the message and pushes both. The `release` workflow refuses a tag that is
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

## 5. A change from another maintainer, or from a contributor

- **A maintainer works as the owner does**: on `main`, with write access, the two gates before every push. One change
  per need the implementation proved, held to sections 2, 3 and 4 as any change is. Its commit names the spec text it
  satisfies or the entry it adds to the spec follow-ups issue; a behaviour the spec does not ask for is that entry
  first, so the spec and every implementation of it move together, and never a surface of this implementation alone.
- **A contributor without write access sends a pull request from a fork**, held to the same sections. A maintainer
  runs `/best-review <number>` on it, which runs the `best-reviewer` skill the same way, posts the findings on the pull
  request and leaves them for the contributor to answer; once the findings are answered and the maintainer has read
  the diff, the maintainer runs the local gate on what would land, its head squashed onto the current `main` (it builds and
  runs the contributor's code), and merges it
  as one commit when that and CI are green. A fork's first workflow run waits for a maintainer's
  approval on the Actions tab.
- **A checkout that runs ahead of `main` on a host is that host's owner's to run**; what the spec promises of it is
  only what `main` proves.

## 6. What we do not do

- No push without `GATE GREEN` and the review: `/best-review` and its `best-reviewer` run on what is pushed, every
  finding fixed or set aside with its reason; the release commit alone skips them.
- No release of a commit the gates have not passed; no tag made by hand.
- No force-push to `main`; no push on top of a red `main`; no merge of a pull request with an unanswered finding, without
  the local gate green on its head, or with a red check.
- No plan file, no `TODO`, no dated narrative: open work is an issue.
