# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --json number,title,body,labels,comments`.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Make an issue a sub-issue of a parent**: `gh issue create --parent <parent> ...`, or `gh issue edit <parent> --add-sub-issue <child>` afterwards (`gh` 2.94+). Older `gh`: `gh api --method POST repos/<owner>/<repo>/issues/<parent>/sub_issues -F sub_issue_id=<child-db-id>` (database id, as in **Blocking** below). Without sub-issues, put `Part of #<parent>` at the top of the child body.
- **Blocking**: GitHub's **native issue dependencies**, the canonical, UI-visible representation. Add an edge with `gh issue create --blocked-by <n>,<n> ...` or `gh issue edit <child> --add-blocked-by <blocker>` (`gh` 2.94+). Older `gh`: `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`, where `<blocker-db-id>` is the blocker's numeric **database id** (`gh api repos/<owner>/<repo>/issues/<n> --jq .id`, _not_ the `#number` or `node_id`). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed.
- **Count open blockers**: `gh api repos/<owner>/<repo>/issues/<n> --jq .issue_dependencies_summary.blocked_by` (open blockers only; 0 means startable). `gh issue view <n> --json blockedBy` also lists closed blockers, so filter it: `--jq '[.blockedBy.nodes[] | select(.state == "OPEN")] | length'`.
- **Comment**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: post the explanation with `gh issue comment <number> --body "..."`, then `gh issue close <number>`. On an already-closed issue, `gh issue close --comment` drops the comment and still exits 0. For implementation deliveries, see **Direct-to-trunk delivery protocol** below before closing.

Infer the repo from `git remote -v`; `gh` does this automatically when run inside a clone.

File issues only into the user's own repo. Never file into `mattpocock/skills` (the repo these skills come from) unless the user owns it. In a fork, `gh` can default to the upstream parent, so before the first `gh issue create` of a session, check the target with `gh repo view --json nameWithOwner` and confirm it with the user if it is not their repo.

## GitHub Actions CI verification

When verifying GitHub Actions runs from automated agent sessions:
- Never invoke `gh run watch` without arguments; interactive TUI prompts will block the agent.
- Query the specific Run ID scoped to the relevant branch and workflow:
  ```bash
  RUN_ID=$(gh run list --branch "<branch>" --workflow "<workflow-name-or-file>" --limit 1 --json databaseId --jq '.[0].databaseId')
  ```
- Validate that a non-empty `RUN_ID` was returned before watching.
- Monitor execution non-interactively using the explicit Run ID and exit code propagation:
  ```bash
  gh run watch "$RUN_ID" --exit-status
  ```
- If the run fails or cannot be found, report the status accurately with logs (`gh run view "$RUN_ID" --log-failed`).

## Direct-to-trunk delivery protocol

When delivering changes directly to `main` (trunk) rather than via pull request, agents must strictly follow the operational lifecycle boundaries below. Direct delivery does not replace or bypass pull requests where repository policy or branch protection rules require them.

### 1. Lifecycle boundaries

Never conflate the three discrete operational phases:
1. **Implementation completion**: Code is implemented, unit/slice tests pass, and fast local verification passes (`./scripts/check.sh`). The working tree is clean. This phase does *not* constitute review approval or verified delivery.
2. **Review approval**: A formal two-axis review (`/code-review` covering Standards and Spec) is completed, all blocking findings are resolved, and the review is signed off. Local verification and review approval are mandatory prerequisites before any push attempt.
3. **Verified remote delivery**: Complete verification passes (`./scripts/check.sh --full` per `AGENTS.md`), the local commit is pushed to the authorized remote branch, verified on remote `main`, and associated CI workflows pass non-interactively to completion.

### 2. Pre-push gates

Before pushing directly to trunk, agents must verify each of the following gates:
- **Local verification passed**: Run `./scripts/check.sh --full` (complete verification per `AGENTS.md`) and ensure zero failures. (During red-green iteration, fast verification `./scripts/check.sh` is used, but delivery to trunk requires full verification).
- **Review approved**: Confirm `/code-review` completed with no unresolved blocking findings.
- **Repository policy & authorization**: Push only when permitted by repository policy and explicitly authorized by the user. If branch protection or repository policy requires pull requests, preserve the PR workflow and do not attempt to bypass branch protection or required reviews.
- **Clean working tree**: Verify `git status` has no unstaged or uncommitted changes.
- **Target branch match**: Verify current branch is the authorized target branch:
  ```bash
  git branch --show-current  # Must output 'main' (or authorized target branch)
  ```
- **Commit identity verification**: Verify the commit to be delivered:
  ```bash
  git log -1 --stat
  COMMIT_SHA=$(git rev-parse HEAD)
  ```

### 3. Delivery and remote verification

Execute the delivery and verify remote persistence:
- **Push to remote**:
  ```bash
  git push origin main
  ```
- **Verify remote existence**: Confirm the remote branch incorporates the expected commit:
  ```bash
  git fetch origin main
  git rev-parse origin/main  # Must equal $COMMIT_SHA
  ```

### 4. Non-interactive CI monitoring

Monitor remote CI execution to completion following the protocol in **GitHub Actions CI verification** above, scoped to the trunk delivery:
```bash
RUN_ID=$(gh run list --branch main --workflow "ci.yml" --limit 1 --json databaseId --jq '.[0].databaseId')
[ -n "$RUN_ID" ] && gh run watch "$RUN_ID" --exit-status
```
If CI fails, inspect logs (`gh run view "$RUN_ID" --log-failed`) and do not proceed to issue closure.

### 5. Verified issue closure

Only after remote verification and CI completion succeed:
- Post the closing comment referencing the verified commit SHA:
  ```bash
  gh issue comment <number> --body "Delivered in commit $COMMIT_SHA with CI verification passing."
  ```
- Close the issue:
  ```bash
  gh issue close <number>
  ```
- Never close an issue at implementation completion or review approval; closure requires verified remote delivery.

## Code Scanning Alerts

When querying, inspecting, dismissing, or verifying GitHub CodeQL code scanning alerts from agent sessions:

- **Fetch alert details**: Inspect rule metadata, CWE classifications, and code flow locations:
  ```bash
  gh api repos/<owner>/<repo>/code-scanning/alerts/<number>
  ```
  Inspection projection:
  ```bash
  gh api repos/<owner>/<repo>/code-scanning/alerts/<number> \
    --jq '{number, rule: .rule.id, description: .rule.description, cwe: .rule.tags, state: .state, location: .most_recent_instance.location}'
  ```

- **Dismiss an alert**: Update state via `PATCH` specifying state, reason, and comment:
  ```bash
  gh api --method PATCH repos/<owner>/<repo>/code-scanning/alerts/<number> \
    -f state="dismissed" \
    -f dismissed_reason="false positive" \
    -f dismissed_comment="Concise technical rationale citing relevant ADRs or domain constraints."
  ```
  Permitted `dismissed_reason` values:
  - `"false positive"`
  - `"won't fix"`
  - `"used in tests"`

- **Character limit ceiling on `dismissed_comment`**:
  > [!WARNING]
  > **Strict 280-character limit**: GitHub's Code Scanning API enforces a strict 280-character ceiling on `dismissed_comment`. Any payload exceeding 280 characters triggers HTTP `422 Unprocessable Entity` errors. Keep technical rationales concise, citing relevant ADRs or domain constraints without fluff.

- **Verify updated alert state**: Validate that the alert state, dismissal reason, and comment were applied:
  ```bash
  gh api repos/<owner>/<repo>/code-scanning/alerts/<number> \
    --jq '{number, state, dismissed_reason, dismissed_comment}'
  ```

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents:

- **Read a PR**: `gh pr view <number>`, then `gh pr view <number> --comments` (off a TTY, `--comments` prints only the comments, not the body), and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh api --paginate 'repos/{owner}/{repo}/pulls?state=open' --jq '.[] | select(.author_association | IN("OWNER","MEMBER","COLLABORATOR") | not) | {number, title, author: .user.login, author_association, labels: [.labels[].name]}'`.
- **Comment / label / close**: `gh pr comment`, `gh pr edit --add-label`/`--remove-label`, `gh pr close`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either: resolve with `gh pr view 42` and fall back to `gh issue view 42`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## Ticket Prerequisite Ownership

When decomposing feature specs into tickets (see `docs/adr/0002-stateless-cookie-sessions-no-database.md`):
- Any cryptographic key, configuration source, or shared prerequisite required for an upstream ticket's externally observable deliverable must be included in that ticket or provided by an already completed dependency.
- Never defer essential prerequisites to downstream tickets.
- Before publishing tickets:
  - Check each ticket's prerequisites.
  - Identify configuration and security dependencies.
  - Ensure upstream deliverables can be implemented and tested independently.
  - Avoid circular dependencies.
  - Keep advanced lifecycle features in the appropriate downstream ticket.


## When a skill says "fetch the relevant ticket"

Read it as in **Read an issue** above.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (see **Make an issue a sub-issue of a parent**). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: see **Blocking** under Conventions.
- **Frontier query**: list the map's open children (`gh issue list --state open`, scoped to the map's sub-issues / task list), drop any with an open blocker (see **Count open blockers**, or an open issue in the `Blocked by` line) or an assignee; first in map order wins.
- **Claim**: `gh issue edit <n> --add-assignee @me`, the session's first write.
- **Resolve**: `gh issue comment <n> --body "<answer>"`, then `gh issue close <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.
