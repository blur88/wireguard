import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify-delivery.sh"
VALID_SHA = "0123456789abcdef0123456789abcdef01234567"
ALT_SHA = "fedcba9876543210fedcba9876543210fedcba98"


def setup_fake_env(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path]:
    """Create isolated sandbox with fake git and gh binaries on PATH."""
    sandbox = tmp_path / "sandbox"
    bin_dir = sandbox / "bin"
    bin_dir.mkdir(parents=True)
    log_file = sandbox / "invocations.log"
    git_state = sandbox / "git_state"
    git_state.mkdir()
    gh_state = sandbox / "gh_state"
    gh_state.mkdir()

    fake_git = bin_dir / "git"
    fake_git.write_text(f"""#!/usr/bin/env bash
set -e
echo "git $*" >> "{log_file}"
if [[ -f "{git_state}/fail_count" ]]; then
  COUNT=$(cat "{git_state}/fail_count")
  if [[ "$COUNT" -gt 0 ]]; then
    echo "$((COUNT - 1))" > "{git_state}/fail_count"
    cat "{git_state}/fail_msg" >&2
    exit 1
  fi
fi
if [[ -f "{git_state}/ls_remote_output" ]]; then
  cat "{git_state}/ls_remote_output"
  exit 0
fi
echo -e "{VALID_SHA}\trefs/heads/main"
exit 0
""")
    fake_git.chmod(0o755)

    fake_gh = bin_dir / "gh"
    fake_gh.write_text(f"""#!/usr/bin/env bash
set -e
echo "gh $*" >> "{log_file}"
if [[ -f "{gh_state}/fail_count" ]]; then
  COUNT=$(cat "{gh_state}/fail_count")
  if [[ "$COUNT" -gt 0 ]]; then
    echo "$((COUNT - 1))" > "{gh_state}/fail_count"
    cat "{gh_state}/fail_msg" >&2
    exit 1
  fi
fi
subcmd="$1"
shift
case "$subcmd" in
  run)
    run_subcmd="$1"
    shift
    case "$run_subcmd" in
      list)
        if [[ -f "{gh_state}/run_list_output" ]]; then
          cat "{gh_state}/run_list_output"
        else
          echo "12345678"
        fi
        exit 0
        ;;
      watch)
        if [[ -f "{gh_state}/watch_exit_code" ]]; then
          exit "$(cat "{gh_state}/watch_exit_code")"
        fi
        exit 0
        ;;
      view)
        if [[ -f "{gh_state}/view_output" ]]; then
          cat "{gh_state}/view_output" >&2
        else
          echo "Sample failure log output" >&2
        fi
        exit 0
        ;;
      *)
        echo "Unknown run subcommand: $run_subcmd" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unknown subcommand: $subcmd" >&2
    exit 1
    ;;
esac
""")
    fake_gh.chmod(0o755)

    return sandbox, log_file, git_state, gh_state


def _read_calls(log_file: Path) -> list[str]:
    if not log_file.exists():
        return []
    return [line.strip() for line in log_file.read_text().splitlines() if line.strip()]


def test_verify_delivery_script_exists_and_is_executable() -> None:
    """Ensure scripts/verify-delivery.sh exists and is executable."""
    assert VERIFY_SCRIPT.is_file(), f"Expected verify-delivery script at {VERIFY_SCRIPT}"
    assert os.access(VERIFY_SCRIPT, os.X_OK), f"Script {VERIFY_SCRIPT} is not executable"


def test_verify_delivery_syntax_bash_n() -> None:
    """Validate bash syntax of scripts/verify-delivery.sh."""
    assert VERIFY_SCRIPT.is_file(), f"Script missing at {VERIFY_SCRIPT}"
    res = subprocess.run(
        ["bash", "-n", str(VERIFY_SCRIPT)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"bash -n failed: {res.stderr}"


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--branch", "main"],
        ["--workflow", "ci.yml"],
    ],
)
def test_verify_delivery_missing_commit_fails(args: list[str]) -> None:
    """Ensure script rejects execution when --commit is omitted."""
    res = subprocess.run(
        [str(VERIFY_SCRIPT), *args],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "Usage:" in res.stderr
    assert "--commit <SHA>" in res.stderr


@pytest.mark.parametrize(
    "bad_sha",
    [
        "12345",
        "0123456789abcdef0123456789abcdef0123456",  # 39 chars
        "0123456789abcdef0123456789abcdef012345678",  # 41 chars
        "0123456789abcdef0123456789abcdef0123456g",  # non-hex 'g'
        "0123456789ABCDEF0123456789ABCDEF01234567",  # uppercase
        "0123456789abcdef0123456789abcdef0123456;",  # injection attempt
        " 0123456789abcdef0123456789abcdef01234567",  # leading space
    ],
)
def test_verify_delivery_malformed_commit_fails(bad_sha: str) -> None:
    """Ensure script rejects commit SHAs that are not exact 40 lowercase hex characters."""
    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", bad_sha],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "invalid commit sha" in res.stderr.lower()


@pytest.mark.parametrize(
    "args",
    [
        ["--commit", VALID_SHA, "--unknown"],
        ["--commit", VALID_SHA, "-c", VALID_SHA],  # short alias not permitted
        ["--commit", VALID_SHA, "--remote", "origin"],  # --remote not permitted
        ["--commit", VALID_SHA, "unexpected-positional"],
    ],
)
def test_verify_delivery_unsupported_flags_fail(args: list[str]) -> None:
    """Ensure script rejects unknown options, aliases, and positional arguments."""
    res = subprocess.run(
        [str(VERIFY_SCRIPT), *args],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "Usage:" in res.stderr


@pytest.mark.parametrize(
    "env_vars",
    [
        {"VERIFY_TIMEOUT_REMOTE": "-5"},
        {"VERIFY_TIMEOUT_REMOTE": "abc"},
        {"VERIFY_TIMEOUT_CI": "0"},
        {"VERIFY_TIMEOUT_CI": "xyz"},
        {"VERIFY_POLL_INTERVAL": "invalid"},
        {"VERIFY_POLL_INTERVAL": "-1"},
    ],
)
def test_verify_delivery_invalid_env_overrides_fail(env_vars: dict[str, str]) -> None:
    """Ensure script validates internal timeout overrides and fails closed on invalid values."""
    env = os.environ.copy()
    env.update(env_vars)
    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "invalid" in res.stderr.lower()


# =========================================================================
# Seam 2: Remote SHA verification (git ls-remote boundary)
# =========================================================================


def test_remote_sha_verification_success(tmp_path: Path) -> None:
    """Ensure matching remote SHA succeeds and queries the correct branch."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (git_state / "ls_remote_output").write_text(f"{VALID_SHA}\trefs/heads/main\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "2"
    env["VERIFY_TIMEOUT_CI"] = "2"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Script failed: {res.stderr}\n{res.stdout}"
    calls = _read_calls(log_file)
    assert any("git ls-remote origin refs/heads/main" in call for call in calls)


def test_remote_sha_transient_failure_then_success(tmp_path: Path) -> None:
    """Ensure script retries on transient git network errors and recovers within deadline."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (git_state / "fail_count").write_text("1")
    (git_state / "fail_msg").write_text(
        "fatal: unable to access 'https://github.com/...': Connection reset\n"
    )
    (git_state / "ls_remote_output").write_text(f"{VALID_SHA}\trefs/heads/main\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "3"
    env["VERIFY_TIMEOUT_CI"] = "2"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Script failed: {res.stderr}\n{res.stdout}"
    calls = _read_calls(log_file)
    git_calls = [c for c in calls if c.startswith("git ls-remote")]
    assert len(git_calls) >= 2


def test_remote_sha_persistent_git_error_fails_with_diagnostics(tmp_path: Path) -> None:
    """Ensure script fails closed when git fails persistently and prints error diagnostics."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (git_state / "fail_count").write_text("99")
    (git_state / "fail_msg").write_text("fatal: remote server returned 502 Bad Gateway\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "Remote verification failed" in res.stderr
    assert "Last git error:" in res.stderr
    assert "502 Bad Gateway" in res.stderr


def test_remote_sha_mismatch_fails_with_diagnostics(tmp_path: Path) -> None:
    """Ensure script fails closed when remote SHA does not match the commit SHA."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (git_state / "ls_remote_output").write_text(f"{ALT_SHA}\trefs/heads/main\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "Remote verification failed" in res.stderr
    assert f"Remote branch returned unexpected commit: {ALT_SHA}" in res.stderr


def test_remote_branch_missing_fails_with_diagnostics(tmp_path: Path) -> None:
    """Ensure script fails closed when remote branch does not exist."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (git_state / "ls_remote_output").write_text("")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "Remote verification failed" in res.stderr
    assert "Remote branch refs/heads/main not found" in res.stderr


def test_remote_sha_custom_branch(tmp_path: Path) -> None:
    """Ensure script respects --branch parameter when querying git remote."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (git_state / "ls_remote_output").write_text(f"{VALID_SHA}\trefs/heads/feature-x\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "2"
    env["VERIFY_TIMEOUT_CI"] = "2"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA, "--branch", "feature-x"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Script failed: {res.stderr}\n{res.stdout}"
    calls = _read_calls(log_file)
    assert any("git ls-remote origin refs/heads/feature-x" in call for call in calls)


# =========================================================================
# Seam 3: GitHub Actions CI verification boundary (gh run list & watch)
# =========================================================================


def test_ci_run_resolution_and_watch_success(tmp_path: Path) -> None:
    """Ensure CI run resolution matches exact SHA/branch/workflow and watches the run ID."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (gh_state / "run_list_output").write_text("987654321\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "2"
    env["VERIFY_TIMEOUT_CI"] = "2"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Script failed: {res.stderr}\n{res.stdout}"
    calls = _read_calls(log_file)
    assert any(
        "gh run list" in call
        and f"--commit {VALID_SHA}" in call
        and "--branch main" in call
        and "--workflow ci.yml" in call
        for call in calls
    )
    assert any("gh run watch 987654321 --exit-status" in call for call in calls)


def test_ci_run_resolution_transient_api_failure_recovery(tmp_path: Path) -> None:
    """Ensure script retries on transient gh API errors and recovers within deadline."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (gh_state / "fail_count").write_text("1")
    (gh_state / "fail_msg").write_text("HTTP 503: Service Unavailable\n")
    (gh_state / "run_list_output").write_text("987654321\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "2"
    env["VERIFY_TIMEOUT_CI"] = "3"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Script failed: {res.stderr}\n{res.stdout}"
    calls = _read_calls(log_file)
    gh_list_calls = [c for c in calls if "gh run list" in c]
    assert len(gh_list_calls) >= 2


def test_ci_run_resolution_not_found_deadline_expiration(tmp_path: Path) -> None:
    """Ensure script fails closed when CI run is not found within deadline."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (gh_state / "run_list_output").write_text("\n")  # Empty output

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_TIMEOUT_CI"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "CI run for commit" in res.stderr
    assert "not found within deadline" in res.stderr


def test_ci_run_resolution_persistent_api_error_fails_with_diagnostics(tmp_path: Path) -> None:
    """Ensure script fails closed with API diagnostics when gh fails persistently."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (gh_state / "fail_count").write_text("99")
    (gh_state / "fail_msg").write_text("HTTP 403: API rate limit exceeded\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_TIMEOUT_CI"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "Last GitHub API error:" in res.stderr
    assert "rate limit exceeded" in res.stderr


def test_ci_run_resolution_rejects_non_numeric_run_id(tmp_path: Path) -> None:
    """Ensure script rejects non-numeric outputs and does not pass them to gh run watch."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (gh_state / "run_list_output").write_text("null\nundefined\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_TIMEOUT_CI"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    calls = _read_calls(log_file)
    assert not any("gh run watch" in call for call in calls)


def test_ci_watch_failed_runs_diagnostics_and_fails_closed(tmp_path: Path) -> None:
    """Ensure script fails closed when CI watch fails and fetches failed logs."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (gh_state / "run_list_output").write_text("987654321\n")
    (gh_state / "watch_exit_code").write_text("1\n")
    (gh_state / "view_output").write_text("Error in step: test failed\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_TIMEOUT_CI"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "CI run 987654321 failed or was cancelled" in res.stderr
    assert "test failed" in res.stderr
    calls = _read_calls(log_file)
    assert any("gh run view 987654321 --log-failed" in call for call in calls)


def test_ci_watch_cancelled_runs_diagnostics_and_fails_closed(tmp_path: Path) -> None:
    """Ensure script fails closed when CI run was cancelled (non-zero watch status)."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (gh_state / "run_list_output").write_text("987654321\n")
    (gh_state / "watch_exit_code").write_text("2\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_TIMEOUT_CI"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [str(VERIFY_SCRIPT), "--commit", VALID_SHA],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "CI run 987654321 failed or was cancelled" in res.stderr


def test_ci_custom_workflow_and_branch(tmp_path: Path) -> None:
    """Ensure script passes explicit branch and workflow arguments to gh run list."""
    sandbox, log_file, git_state, gh_state = setup_fake_env(tmp_path)
    (git_state / "ls_remote_output").write_text(f"{VALID_SHA}\trefs/heads/release-1\n")
    (gh_state / "run_list_output").write_text("456789\n")

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["VERIFY_TIMEOUT_REMOTE"] = "1"
    env["VERIFY_TIMEOUT_CI"] = "1"
    env["VERIFY_POLL_INTERVAL"] = "0.05"

    res = subprocess.run(
        [
            str(VERIFY_SCRIPT),
            "--commit",
            VALID_SHA,
            "--branch",
            "release-1",
            "--workflow",
            "release.yml",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Script failed: {res.stderr}\n{res.stdout}"
    calls = _read_calls(log_file)
    assert any(
        "gh run list" in call and "--branch release-1" in call and "--workflow release.yml" in call
        for call in calls
    )
    assert any("gh run watch 456789 --exit-status" in call for call in calls)


# =========================================================================
# Seam 4: Documentation integration & preservation of delivery gates
# =========================================================================


def test_documentation_invokes_verify_delivery_script() -> None:
    """Ensure docs/agents/issue-tracker.md invokes scripts/verify-delivery.sh."""
    doc_path = REPO_ROOT / "docs" / "agents" / "issue-tracker.md"
    assert doc_path.is_file(), f"Missing doc file {doc_path}"
    content = doc_path.read_text()

    assert "scripts/verify-delivery.sh --commit" in content
    # Ensure inline polling loops are removed from markdown instructions
    assert 'awk \'$2 == "refs/heads/main"' not in content
    assert "DEADLINE=$((SECONDS + 30))" not in content
    assert "DEADLINE=$((SECONDS + 60))" not in content


def test_documentation_preserves_delivery_and_closure_gates() -> None:
    """Ensure docs/agents/issue-tracker.md preserves essential gates and manual steps."""
    doc_path = REPO_ROOT / "docs" / "agents" / "issue-tracker.md"
    content = doc_path.read_text()

    # Pre-push and verification gates preserved
    assert "./scripts/check.sh --full" in content
    assert "/code-review" in content
    assert "git push origin main" in content

    # Issue closure gates preserved
    assert "gh issue comment" in content
    assert "gh issue close" in content
    assert "Never close an issue at implementation completion or review approval" in content


def test_documentation_code_scanning_dismissal_lifecycle() -> None:
    """Ensure docs/agents/issue-tracker.md defines CodeQL alert dismissal lifecycle rules."""
    doc_path = REPO_ROOT / "docs" / "agents" / "issue-tracker.md"
    content = doc_path.read_text()

    # Code scanning alerts section
    assert "## Code Scanning Alerts" in content
    assert "Dismissal lifecycle" in content

    # Code-dependent delivery and CI verification requirement
    assert "When an alert dismissal rationale depends on newly changed code" in content
    assert "verified remote delivery" in content

    # Resolution as fixed and reassessment
    assert (
        "allow normal resolution as fixed" in content.lower()
        or "automatically resolve the alert as `fixed`" in content
    )
    assert (
        "do not unnecessarily dismiss fixed alerts" in content
        or "do not manually dismiss alerts that resolve as fixed" in content
    )

    # Pending analysis caution
    assert "do not claim" in content
    assert "pending" in content

    # False positive preservation and existing API requirements
    assert "Pre-existing safeguards" in content or "genuine false positives" in content.lower()
    assert "Strict 280-character limit" in content
    assert "Permitted `dismissed_reason` values" in content
