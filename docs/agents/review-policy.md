# Review Policy & Finding Classification

This document defines the review classification standards and lifecycle rules for code reviews across this repository.

## Finding Classification

Every finding identified during code review must be explicitly classified into one of five categories, accompanied by a clear rationale and supporting evidence (spec citation, file and line number, or command output):

1. **Blocking**:
   - A direct violation of an explicit issue acceptance criterion, specification requirement, security vulnerability, broken functionality, or documented repository standard (such as ADR rules or `GLOSSARY.md` constraints).
   - Must be resolved with a failing test and fix prior to merge.

2. **Non-Blocking**:
   - Constructive suggestions, minor code smells, or non-functional improvements that do not violate acceptance criteria, break functionality, or introduce security issues.
   - Author may address immediately or accept without blocking merge.

3. **Accepted**:
   - A conscious trade-off or minor code smell that has been reviewed, evaluated, and explicitly deemed acceptable by the author or project owner without requiring code changes.
   - **Lifecycle Rule**: Once a finding is classified as Accepted, reviewers must not reintroduce it as a blocker in subsequent review rounds without material new evidence.

4. **Deferred**:
   - A valid requirement or enhancement that is explicitly out of scope for the current ticket and assigned to a subsequent ticket or tracked on an existing future issue (with testable acceptance criteria).
   - **Lifecycle Rule**: Must not block the current ticket.

5. **Duplicate**:
   - A finding that repeats or overlaps with an already recorded finding or symptom of the same root issue.

## Ground Rules

- **No Churn on Accepted Findings**: Reviewers must respect previous review dispositions. Style preferences or previously accepted cosmetic items must not restart review cycles.
- **No Suppression of Genuine Defects**: This policy does not suppress genuine new security vulnerabilities, regressions, specification breaches, or correctness issues.
- **Upstream Skill Preservation**: Applied within repo governance; does not fork or modify upstream agent skills.
