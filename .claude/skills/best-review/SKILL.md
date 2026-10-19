---
name: best-review
description: The review gate of a best-peer pull request (SDLC.md section 4, gate 3), run by the author's assistant on the branch once the pull request is open. Gets the findings from the `best-reviewer` skill, which runs with an empty context on the model it pins, posts them on the pull request as a comment-only review, then verifies each one against the code, fixes the real ones with a test, runs the local gate, replies on every thread and pushes. Use when a pull request has just been opened or pushed, when asked to review the pull request, to answer the review, or to run gate 3; `/best-review` is how a maintainer types it.
argument-hint: [pull-request number]
effort: high
---

# Review

Gate 3 of every best-peer pull request. The findings come from a reviewer that has not seen this conversation and runs
on the model the `best-reviewer` skill pins; this session verifies, fixes and answers them. Nothing here approves or
merges the pull request: the owner merges, after the review is answered and CI is green.

## 1. The pull request

```bash
gh repo view --json nameWithOwner -q .nameWithOwner
gh pr view $ARGUMENTS --json number,url,state,isDraft,baseRefName,headRefName,headRefOid,author
git fetch origin && git status --short --branch
```

- No open pull request for this branch and no number given: say so in one line and stop.
- The local branch must be the pull request's head, clean, and at `headRefOid`; otherwise stop and say what differs.
  Never switch branches, stash or discard anything to get there.
- Findings already on the pull request from a previous run: the inline comments AND the review bodies that start with
  `**best-review**` (a finding on an unchanged line lives in a body, not inline). Collect path, line and summary from
  both so the reviewer is told not to repeat them.

```bash
gh api repos/<owner/repo>/pulls/<n>/comments --paginate --jq '.[] | select(.body | startswith("**best-review**")) | {id, path, line, body}'
gh api repos/<owner/repo>/pulls/<n>/reviews --paginate --jq '.[] | select(.body | startswith("**best-review**")) | {id, body}'
```

## 2. The findings

Invoke the `best-reviewer` skill with the pull request number as the first word of its arguments and, after it, the
already-reported findings if any. It forks on its own model and returns a `FINDINGS` block with every finding it has;
the block is never truncated, so what it returns is the whole review. If the Skill tool cannot run it, spawn one Agent
(general-purpose) with `model: "sonnet"` (the Agent tool takes aliases, and the alias is what pins it on this path)
and `effort: "high"`, whose prompt is the body of `.claude/skills/best-reviewer/SKILL.md` with the arguments filled
in; never review in this session's own context, which wrote the code.

## 3. Post the review, comment only

Build one review from the block and post it before touching any code, so the record shows what was found, not what
was left after the fixes:

```bash
gh api repos/<owner/repo>/pulls/<n>/reviews --input <scratch dir>/review.json
```

`review.json` is written in the session's scratchpad directory (or the system temp directory), never inside the
checkout, so the branch stays clean and nothing can be committed by mistake:

```json
{
  "event": "COMMENT",
  "body": "**best-review** on <head sha, 7 chars>: <n> defects, <m> questions. Findings on unchanged lines are listed here; the rest are inline.\n\n<one bullet per finding with line 0: path, summary, failure>",
  "comments": [
    { "path": "<path>", "line": <line>, "side": "RIGHT",
      "body": "**best-review** <defect|question>: <summary>\n\nFailure: <failure>\nFix: <fix>" }
  ]
}
```

Before posting, check every inline comment's `path` and `line` against the hunks of `gh pr diff <n>`: a line that is
not on the new side of the diff goes into the body as a line-0 finding instead, because GitHub rejects the whole
review (422) for one bad anchor. If the post is still rejected, move the comment it names into the body and post
again; no finding is dropped.

`FINDINGS none` posts a review with the body `**best-review** on <sha>: no findings.` and no comments. The event is
always `COMMENT`; never `APPROVE` or `REQUEST_CHANGES`. Then read the inline comments back to get their ids:

```bash
gh api repos/<owner/repo>/pulls/<n>/comments --paginate --jq '.[] | select(.pull_request_review_id == <review id>) | {id, path, line}'
```

## 4. Verify, fix, answer

For every finding, in order:

1. **Verify** it against the code yourself. A finding you cannot reproduce from the code is answered, not fixed.
2. **Fix** a real defect on this branch: a test on the fakes that fails without the fix where one applies, then the
   fix, matching the surrounding code and comments. A finding that reveals a design error, or a behaviour the spec
   does not ask for with no entry on the spec follow-ups issue, is not patched: say so in the reply and in the chat,
   and stop before the code moves; that goes back to the issue first.
3. **The local gate** again, as `SDLC.md` section 4 gate 1 asks: `scripts/gate.sh all` (`pwsh scripts/gate.ps1 all` on
   Windows) must end in `GATE GREEN`. A red gate is reported as red, with the step that failed.
4. **Commit** once for all the fixes (or once per finding when they are unrelated), the subject one plain sentence
   saying what changed and why, starting `Review:`, the body naming the findings, ending with the attribution line
   this session uses. Line endings as they were (`git diff --stat --ignore-cr-at-eol` shows no whole-file churn).
5. **Reply** on each thread:

   ```bash
   gh api repos/<owner/repo>/pulls/<n>/comments/<comment id>/replies -f body='<reply>'
   ```

   Fixed: `Fixed in <sha>: <what changed>.` and resolve the thread. Not a defect: `Not a defect: <why, from the code>.`,
   thread left open for the owner to judge. A question: the answer, thread left open. Findings that were in the
   review body (line 0) are answered in one comment on the pull request (`gh pr comment <n> --body ...`).

   Resolving a thread:

   ```bash
   gh api graphql -f query='query($o:String!,$r:String!,$n:Int!,$c:String){repository(owner:$o,name:$r){pullRequest(number:$n){reviewThreads(first:100,after:$c){pageInfo{hasNextPage endCursor} nodes{id isResolved comments(first:1){nodes{databaseId}}}}}}}' -F o=<owner> -F r=<repo> -F n=<n>
   gh api graphql -f query='mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}' -F id=<thread id>
   ```

   While `hasNextPage` is true, repeat the query with `-F c=<endCursor>` until the thread is found.

6. **Push** the branch, never with force. CI (gate 2) runs on the new head. A later push by the author is reviewed
   again by the same command, and that run reviews only what is new, because step 1 passes the reported findings along.

## 5. Report

In chat, one block and nothing longer:

```
**<owner/repo>#<n>** <pull request url>
- fixed: <the defect in half a sentence> (<sha>)
- not a defect: <the finding> — <why>
- question: <the question> — <the answer>
- owner's call: <what needs a decision>
gate: GREEN on <sha>
```

`no findings` when the reviewer reported none. Approve nothing; merge nothing.
