#!/usr/bin/env bash
set -euo pipefail

# scripts/check.sh: Centralized local check runner for wireguard-dashboard
# Supports:
#   ./scripts/check.sh         - Linting, formatting check, strict typechecking, fast test suite
#   ./scripts/check.sh --full  - Complete verification including Docker container integration tests

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# Prefer virtual environment binaries if present
if [[ -d ".venv/bin" ]]; then
    export PATH="${REPO_ROOT}/.venv/bin:${PATH}"
fi

MODE="fast"

if [[ $# -eq 0 ]]; then
    MODE="fast"
elif [[ $# -eq 1 && "$1" == "--full" ]]; then
    MODE="full"
else
    echo "Error: Unsupported argument(s): $*" >&2
    echo "Usage: $0 [--full]" >&2
    exit 2
fi

echo "=================================================="
echo "Running static analysis: ruff check"
echo "=================================================="
ruff check .

echo "=================================================="
echo "Running formatting check: ruff format --check"
echo "=================================================="
ruff format --check .

echo "=================================================="
echo "Running strict typechecking: mypy"
echo "=================================================="
mypy src tests --strict

if [[ "${MODE}" == "full" ]]; then
    echo "=================================================="
    echo "Verifying Docker availability for full test tier"
    echo "=================================================="
    if ! command -v docker >/dev/null 2>&1; then
        echo "Error: Docker command not found. Container verification requires Docker." >&2
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        echo "Error: Docker daemon is not running or accessible. Full verification failed." >&2
        exit 1
    fi

    echo "=================================================="
    echo "Running FULL test suite (including container integration tests)"
    echo "=================================================="
    pytest -v
    echo "=================================================="
    echo "All checks passed! [Tiers executed: Lint, Format, Mypy Strict, Fast Tests, Container Tests, Packaging]"
    echo "=================================================="
else
    echo "=================================================="
    echo "Running FAST test suite (excluding container tests)"
    echo "=================================================="
    pytest -m "not container" -v
    echo "=================================================="
    echo "Fast checks passed! [Tiers executed: Lint, Format, Mypy Strict, Fast Tests]"
    echo "Note: Container tests were excluded. Run './scripts/check.sh --full' for complete verification."
    echo "=================================================="
fi
