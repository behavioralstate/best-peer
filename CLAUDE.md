# CLAUDE.md

How this repository is built and shipped is [`SDLC.md`](SDLC.md), the one place the lifecycle is written down; read it
before changing anything, and keep it the current rule when a change moves the process. In short:

- Starting on an issue, move it to In progress on the Behavioralstate board first (project 4 of Amarcode-Studios, its
  Status field: `gh project item-edit`, or the board itself), and its epic to In progress if it was not; once its code is
  in a release, with only a host proof or the owner's acceptance left, move it to In review (SDLC.md
  section 1). An issue carries its one epic's label (`best-peer-01`, `windlet-02`), the label the epic carries
  beside `epic`, and no other epic's.
- Every change is made on `main` and pushed there, the owner's and every maintainer's; no branch and no pull request
  is needed. The subject is one plain sentence saying what changed and why, with no type prefix (`feat:`, `fix:`);
  the one prefix is `Review:` on a commit that answers the review, as the history has it. Open work is an issue on
  the Behavioralstate board, never a plan file or a `TODO`. `git pull --rebase` before the gates; after a rebase
  that brought commits in, the local gate runs again on the new head, and the review runs again when the rebase
  changed one's own commits (a conflict resolved). A red `main` is fixed before anything else is
  pushed.
- Two gates before every push, both mandatory. First the local proof: `scripts/gate.sh all` (`pwsh scripts/gate.ps1
  all` on Windows) must end in `GATE GREEN`; CI runs the same script on the push. Then the review: `/best-review`
  always runs `.claude/skills/best-reviewer` on a separate worker with the model that skill pins, on what `main`
  holds that `origin/main` does not, and this session fixes every finding on `main` with a test, in a `Review:`
  commit that names them, or sets it aside with its reason in that message (an empty commit when nothing changed).
  The local gate then runs on the head that is pushed. Nothing is pushed until both are done.
- A contributor without write access sends a pull request from a fork; `/best-review <number>` reviews it the same
  way and posts the findings there. A maintainer merges it once they are answered, the local gate is green on what would land, its head squashed onto `main` (run only after its diff has been read, since it runs the contributor's code) and CI is green.
- The BEST spec is stable (behavioralstate/spec#37 holds the rule). A behaviour the spec does not mention is
  best-peer's own, documented in the README: never an entry on #37, a spec issue or a spec pull request, and never a
  review finding. Only the owner changes the spec, on proof that two independent implementations read the same
  sentence differently and a client failed; a session that believes it holds that proof brings it to the owner in
  the chat and stops. An adapter is proven on a host by hand, with the proof on the slice's issue.
- The README's "Try it on your machine" and Run sections move in the same commit as the variable, the check at start,
  the command or the sign-in they describe.
