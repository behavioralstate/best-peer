# CLAUDE.md

How this repository is built and shipped is [`SDLC.md`](SDLC.md), the one place the lifecycle is written down; read it
before changing anything, and keep it the current rule when a change moves the process. In short:

- Starting on an issue, move it to In progress on the Behavioralstate board first (project 4 of Amarcode-Studios, its
  Status field: `gh project item-edit`, or the board itself), and its epic to Ready if it was not; once its code is
  merged and released, with only a host proof or the owner's acceptance left, move it to In review (SDLC.md
  section 1).
- Every change is a branch and a pull request to `main`, squash-merged as one commit, the owner's included. The
  subject is one plain sentence saying what changed and why, with no type prefix (`feat:`, `fix:`); the one prefix
  is `Review:` on a commit that answers the review, as the history has it. Open work is an issue on the
  Behavioralstate board, never a plan file or a `TODO`.
- Before the push, the local proof: `scripts/gate.sh all` (`pwsh scripts/gate.ps1 all` on Windows) must end in
  `GATE GREEN`. CI runs the same script, so what passes here passes there.
- Once the pull request is open, its review: `/best-review` runs `.claude/skills/best-reviewer` on a separate worker
  with the model that skill pins, posts the findings on the pull request, and this session answers every one on its
  thread with a fix and a test, or the reason it stands. The owner merges.
- A behaviour the spec does not ask for is an entry on the spec follow-ups issue, behavioralstate/spec#37, before it
  is a pull request. An adapter is proven on a host by hand, with the proof on the slice's issue.
- The README's "Try it on your machine" and Run sections move in the same commit as the variable, the check at start,
  the command or the sign-in they describe.
