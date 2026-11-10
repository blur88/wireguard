import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check.sh"


def setup_fake_runner_env(
    tmp_path: Path, tool_overrides: dict[str, str] | None = None
) -> tuple[Path, Path, Path]:
    """Create an isolated sandbox with fake executables to trace check runner calls."""
    sandbox_root = tmp_path / "sandbox"
    scripts_dir = sandbox_root / "scripts"
    scripts_dir.mkdir(parents=True)
    runner = scripts_dir / "check.sh"
    shutil.copy2(CHECK_SCRIPT, runner)
    runner.chmod(0o755)

    fake_venv_bin = sandbox_root / ".venv" / "bin"
    fake_venv_bin.mkdir(parents=True)

    log_file = sandbox_root / "invocations.log"
    (sandbox_root / "src").mkdir()
    (sandbox_root / "tests").mkdir()

    tools = ["ruff", "mypy", "pytest", "docker"]
    for tool in tools:
        custom_body = (tool_overrides or {}).get(tool)
        if custom_body is not None:
            script_content = custom_body
        else:
            script_content = f'#!/bin/sh\necho "$(basename "$0") $*" >> "{log_file}"\nexit 0\n'
        tool_file = fake_venv_bin / tool
        tool_file.write_text(script_content)
        tool_file.chmod(0o755)

    return runner, log_file, sandbox_root


def test_check_script_exists_and_is_executable() -> None:
    """Ensure scripts/check.sh exists and has execute permissions."""
    assert CHECK_SCRIPT.is_file(), f"Expected check runner script at {CHECK_SCRIPT}"
    assert os.access(CHECK_SCRIPT, os.X_OK), f"Script {CHECK_SCRIPT} is not executable"


@pytest.mark.parametrize(
    "args",
    [
        ["--invalid-flag"],
        ["--fix", "--full"],
        ["--full", "--fix"],
        ["--fix", "--invalid"],
        ["--fix", "extra-arg"],
    ],
)
def test_check_script_rejects_unsupported_and_conflicting_arguments(
    args: list[str],
) -> None:
    """Ensure check.sh rejects unknown options and conflicting combinations with exit code 2."""
    res = subprocess.run(
        [str(CHECK_SCRIPT), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    combined = res.stderr + res.stdout
    assert "Usage:" in combined
    assert "[--full | --fix]" in combined
    assert "unsupported" in combined.lower()


def test_check_script_full_requires_docker_or_fails(tmp_path: Path) -> None:
    """Ensure check.sh --full fails with non-zero exit if Docker daemon is not accessible."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text("#!/bin/sh\nexit 1\n")
    fake_docker.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.path.pathsep}{env.get('PATH', '')}"

    res = subprocess.run(
        [str(CHECK_SCRIPT), "--full"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode != 0
    combined = (res.stdout + res.stderr).lower()
    assert "docker" in combined


def test_check_script_fix_executes_expected_sequence_and_excludes_container(
    tmp_path: Path,
) -> None:
    """Ensure --fix executes fix/format commands before verification and excludes Docker tests."""
    runner, log_file, sandbox_root = setup_fake_runner_env(tmp_path)

    res = subprocess.run(
        [str(runner), "--fix"],
        cwd=sandbox_root,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"Script failed with output:\n{res.stdout}\n{res.stderr}"

    recorded_calls = [line.strip() for line in log_file.read_text().splitlines() if line.strip()]

    expected_sequence = [
        "ruff check --fix .",
        "ruff format .",
        "ruff check .",
        "ruff format --check .",
        "mypy src tests --strict",
        "pytest -m not container -v",
    ]
    assert recorded_calls == expected_sequence
    assert not any("docker" in call for call in recorded_calls)


def test_check_script_default_and_full_are_strictly_read_only(
    tmp_path: Path,
) -> None:
    """Ensure default run and --full remain strictly read-only and never trigger writes."""
    runner, log_file, sandbox_root = setup_fake_runner_env(tmp_path)

    # 1. Default run
    res_default = subprocess.run(
        [str(runner)],
        cwd=sandbox_root,
        capture_output=True,
        text=True,
    )
    assert res_default.returncode == 0, res_default.stderr
    default_calls = [line.strip() for line in log_file.read_text().splitlines() if line.strip()]
    assert "ruff check --fix ." not in default_calls
    assert "ruff format ." not in default_calls
    assert default_calls == [
        "ruff check .",
        "ruff format --check .",
        "mypy src tests --strict",
        "pytest -m not container -v",
    ]

    # Reset log for full verification run
    log_file.unlink()

    # 2. --full run
    res_full = subprocess.run(
        [str(runner), "--full"],
        cwd=sandbox_root,
        capture_output=True,
        text=True,
    )
    assert res_full.returncode == 0, res_full.stderr
    full_calls = [line.strip() for line in log_file.read_text().splitlines() if line.strip()]
    assert "ruff check --fix ." not in full_calls
    assert "ruff format ." not in full_calls
    assert full_calls == [
        "ruff check .",
        "ruff format --check .",
        "mypy src tests --strict",
        "docker info",
        "pytest -v",
    ]


@pytest.mark.parametrize(
    ("failing_tool", "expected_executed_calls"),
    [
        ("ruff_fix", ["ruff check --fix ."]),
        ("ruff_format", ["ruff check --fix .", "ruff format ."]),
        (
            "mypy",
            [
                "ruff check --fix .",
                "ruff format .",
                "ruff check .",
                "ruff format --check .",
                "mypy src tests --strict",
            ],
        ),
    ],
)
def test_check_script_fail_fast_preserves_exit_code_and_aborts_early(
    tmp_path: Path, failing_tool: str, expected_executed_calls: list[str]
) -> None:
    """Ensure check.sh --fix halts immediately with non-zero exit code upon any step failure."""
    log_file = tmp_path / "invocations.log"
    ruff_script = (
        "#!/bin/sh\n"
        f'echo "$(basename "$0") $*" >> "{log_file}"\n'
        'if [ "$1" = "check" ] && [ "$2" = "--fix" ] && [ "'
        + failing_tool
        + '" = "ruff_fix" ]; then\n'
        "  exit 1\n"
        "fi\n"
        'if [ "$1" = "format" ] && [ "$2" != "--check" ] && [ "'
        + failing_tool
        + '" = "ruff_format" ]; then\n'
        "  exit 1\n"
        "fi\n"
        "exit 0\n"
    )
    mypy_script = (
        "#!/bin/sh\n"
        f'echo "$(basename "$0") $*" >> "{log_file}"\n'
        'if [ "' + failing_tool + '" = "mypy" ]; then exit 1; fi\n'
        "exit 0\n"
    )

    runner, _, sandbox_root = setup_fake_runner_env(
        tmp_path,
        tool_overrides={"ruff": ruff_script, "mypy": mypy_script},
    )

    res = subprocess.run(
        [str(runner), "--fix"],
        cwd=sandbox_root,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    recorded_calls = [line.strip() for line in log_file.read_text().splitlines() if line.strip()]
    assert recorded_calls == expected_executed_calls
