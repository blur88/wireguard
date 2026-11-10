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

Run `./scripts/check.sh` for fast local verification (lint, format, strict typechecking, fast unit/HTTP tests). Run `./scripts/check.sh --full` for complete verification (includes Docker container integration tests). Complete verification (`--full`) is required before PR creation and merge; fast verification must not be represented as full verification.
