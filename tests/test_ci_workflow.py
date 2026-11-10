from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_workflow_exists_and_is_valid_yaml() -> None:
    """Ensure .github/workflows/ci.yml exists and parses as valid YAML."""
    assert CI_WORKFLOW.is_file(), f"Missing CI workflow file at {CI_WORKFLOW}"
    with open(CI_WORKFLOW, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "CI workflow must be a valid YAML mapping"


def test_ci_workflow_triggers_on_push_and_pr_to_main() -> None:
    """Ensure workflow triggers on push to main and pull_request to main."""
    with open(CI_WORKFLOW, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    # In YAML, 'on' may parse as True boolean if unquoted or 'on' string if quoted
    triggers = data.get("on") or data.get(True)
    assert triggers is not None, "Workflow must define triggers ('on')"

    assert "push" in triggers, "Workflow must trigger on 'push'"
    assert "main" in triggers["push"]["branches"]

    assert "pull_request" in triggers, "Workflow must trigger on 'pull_request'"
    assert "main" in triggers["pull_request"]["branches"]


def test_ci_workflow_executes_check_runner_or_guardrails() -> None:
    """Ensure workflow runs the check runner or guardrail commands (ruff, mypy, pytest)."""
    with open(CI_WORKFLOW, encoding="utf-8") as f:
        content = f.read()

    assert "scripts/check.sh" in content or (
        "ruff" in content and "mypy" in content and "pytest" in content
    )
    # Ensure --full or container tests are invoked
    assert "--full" in content or "container" in content
