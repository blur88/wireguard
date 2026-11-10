## Agent skills

### Issue tracker

GitHub issues via `gh` CLI (`blur88/wireguard`). See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical five-role triage labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context (`GLOSSARY.md` + `docs/adr/`). See `docs/agents/domain.md`.

### Review policy

Five-category finding classification (`blocking`, `non-blocking`, `accepted`, `deferred`, `duplicate`). See `docs/agents/review-policy.md`.

### Verification

During red-green TDD, prefer focused pytest execution for rapid feedback. After completing an implementation slice, run the fast repository checks. Use `--fix` only when automatic source modifications are explicitly intended. Run `--full` before PR creation and merge.

Preferred workflow:
1. Focused pytest during red-green iteration.
2. `./scripts/check.sh` for read-only fast verification (lint, format, strict typechecking, fast unit/HTTP tests), or `--fix` when explicitly authorized.
3. `./scripts/check.sh --full` for complete verification (includes Docker container integration tests) before PR preparation and merge; fast verification must not be represented as full verification.
