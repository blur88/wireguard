import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_SCRIPT = REPO_ROOT / "scripts" / "check.sh"


def test_check_script_exists_and_is_executable() -> None:
    """Ensure scripts/check.sh exists and has execute permissions."""
    assert CHECK_SCRIPT.is_file(), f"Expected check runner script at {CHECK_SCRIPT}"
    assert os.access(CHECK_SCRIPT, os.X_OK), f"Script {CHECK_SCRIPT} is not executable"


def test_check_script_rejects_unsupported_arguments() -> None:
    """Ensure check.sh rejects unknown options with a non-zero exit code."""
    res = subprocess.run(
        [str(CHECK_SCRIPT), "--invalid-flag"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert (
        "Usage:" in res.stderr
        or "Usage:" in res.stdout
        or "unsupported" in res.stderr.lower()
        or "unsupported" in res.stdout.lower()
    )


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
