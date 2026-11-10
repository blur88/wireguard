import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_pytest_registers_container_marker() -> None:
    """Ensure container marker is registered in pytest to avoid unknown marker warnings."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "--markers",
    ]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    assert "container" in res.stdout, "Custom marker 'container' is not registered in pytest config"


def test_fast_test_collection_excludes_container_marked_tests() -> None:
    """Ensure 'pytest -m \"not container\"' deselects container tests and selects fast tests."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-m",
        "not container",
        "--collect-only",
        "-q",
    ]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    output = res.stdout

    # Must collect healthz, config, html_shell, package tests
    assert "test_healthz.py" in output
    assert "test_config.py" in output
    assert "test_html_shell.py" in output
    assert "test_package.py" in output
    # Must NOT select test_container.py tests
    assert "test_container.py" not in output


def test_container_marker_selection_collects_container_tests() -> None:
    """Ensure 'pytest -m container' selects only container tests."""
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-m",
        "container",
        "--collect-only",
        "-q",
    ]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    output = res.stdout

    assert "test_container.py" in output
    assert "test_healthz.py" not in output
    assert "test_config.py" not in output
