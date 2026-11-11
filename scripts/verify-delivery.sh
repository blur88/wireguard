#!/usr/bin/env bash
set -euo pipefail

# scripts/verify-delivery.sh: Remote commit delivery and GitHub Actions CI verification.
#
# Usage:
#   scripts/verify-delivery.sh --commit <SHA> [--branch <BRANCH>] [--workflow <WORKFLOW>]

usage() {
  echo "Usage: $0 --commit <SHA> [--branch <BRANCH>] [--workflow <WORKFLOW>]" >&2
  exit 2
}

COMMIT_SHA=""
BRANCH="main"
WORKFLOW="ci.yml"
REMOTE="origin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit)
      [[ $# -ge 2 ]] || usage
      COMMIT_SHA="$2"
      shift 2
      ;;
    --branch)
      [[ $# -ge 2 ]] || usage
      BRANCH="$2"
      shift 2
      ;;
    --workflow)
      [[ $# -ge 2 ]] || usage
      WORKFLOW="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [[ -z "${COMMIT_SHA}" ]]; then
  echo "Error: Missing required argument --commit <SHA>." >&2
  usage
fi

if ! [[ "${COMMIT_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Error: Invalid commit SHA: '${COMMIT_SHA}'. Must be a 40-character lowercase hexadecimal string." >&2
  exit 2
fi

if [[ -z "${BRANCH}" ]]; then
  echo "Error: --branch cannot be empty." >&2
  exit 2
fi

if [[ -z "${WORKFLOW}" ]]; then
  echo "Error: --workflow cannot be empty." >&2
  exit 2
fi

# Internal timing configurations (overridable for test acceleration)
TIMEOUT_REMOTE="${VERIFY_TIMEOUT_REMOTE:-30}"
TIMEOUT_CI="${VERIFY_TIMEOUT_CI:-60}"
POLL_INTERVAL_REMOTE="${VERIFY_POLL_INTERVAL:-2}"
POLL_INTERVAL_CI="${VERIFY_POLL_INTERVAL:-5}"

if ! [[ "${TIMEOUT_REMOTE}" =~ ^[1-9][0-9]*$ ]]; then
  echo "Error: Invalid VERIFY_TIMEOUT_REMOTE: '${TIMEOUT_REMOTE}'. Must be a positive integer." >&2
  exit 2
fi

if ! [[ "${TIMEOUT_CI}" =~ ^[1-9][0-9]*$ ]]; then
  echo "Error: Invalid VERIFY_TIMEOUT_CI: '${TIMEOUT_CI}'. Must be a positive integer." >&2
  exit 2
fi

is_positive_number() {
  local val="$1"
  if [[ "${val}" =~ ^[1-9][0-9]*$ ]]; then
    return 0
  fi
  if [[ "${val}" =~ ^([0-9]*\.[0-9]+|[0-9]+\.[0-9]*)$ ]]; then
    if [[ "${val}" =~ [1-9] ]]; then
      return 0
    fi
  fi
  return 1
}

if ! is_positive_number "${POLL_INTERVAL_REMOTE}"; then
  echo "Error: Invalid VERIFY_POLL_INTERVAL: '${POLL_INTERVAL_REMOTE}'. Must be a positive number." >&2
  exit 2
fi

if ! is_positive_number "${POLL_INTERVAL_CI}"; then
  echo "Error: Invalid VERIFY_POLL_INTERVAL: '${POLL_INTERVAL_CI}'. Must be a positive number." >&2
  exit 2
fi

echo "Verifying remote delivery for commit ${COMMIT_SHA} on ${REMOTE} refs/heads/${BRANCH}..."

# Step 1: Remote commit verification
DEADLINE_REMOTE=$((SECONDS + TIMEOUT_REMOTE))
REMOTE_SHA=""
LAST_GIT_ERR=""
LAST_GIT_SEEN=""

while [[ ${SECONDS} -lt ${DEADLINE_REMOTE} ]]; do
  if OUTPUT=$(git ls-remote "${REMOTE}" "refs/heads/${BRANCH}" 2>&1); then
    LAST_GIT_ERR=""
    PARSED_SHA=$(echo "${OUTPUT}" | awk -v branch="refs/heads/${BRANCH}" '$2 == branch {print $1; exit}')
    LAST_GIT_SEEN="${PARSED_SHA}"
    if [[ -n "${PARSED_SHA}" && "${PARSED_SHA}" == "${COMMIT_SHA}" ]]; then
      REMOTE_SHA="${PARSED_SHA}"
      break
    fi
  else
    LAST_GIT_ERR="${OUTPUT}"
  fi
  sleep "${POLL_INTERVAL_REMOTE}"
done

if [[ -z "${REMOTE_SHA}" || "${REMOTE_SHA}" != "${COMMIT_SHA}" ]]; then
  echo "Error: Remote verification failed for commit ${COMMIT_SHA} on branch ${BRANCH} within deadline." >&2
  if [[ -n "${LAST_GIT_ERR}" ]]; then
    echo "Last git error: ${LAST_GIT_ERR}" >&2
  elif [[ -n "${LAST_GIT_SEEN}" ]]; then
    echo "Remote branch returned unexpected commit: ${LAST_GIT_SEEN}" >&2
  else
    echo "Remote branch refs/heads/${BRANCH} not found." >&2
  fi
  exit 1
fi

echo "Remote delivery verified for commit ${COMMIT_SHA}."

# Step 2: GitHub Actions CI run resolution and non-interactive monitoring
echo "Resolving GitHub Actions CI run for commit ${COMMIT_SHA} (workflow: ${WORKFLOW}, branch: ${BRANCH})..."
DEADLINE_CI=$((SECONDS + TIMEOUT_CI))
RUN_ID=""
LAST_GH_ERR=""

while [[ ${SECONDS} -lt ${DEADLINE_CI} ]]; do
  if OUTPUT=$(gh run list --commit "${COMMIT_SHA}" --branch "${BRANCH}" --workflow "${WORKFLOW}" --json databaseId,headSha --jq ".[] | select(.headSha == \"${COMMIT_SHA}\") | .databaseId" 2>&1); then
    LAST_GH_ERR=""
    PARSED_RUN_ID=$(echo "${OUTPUT}" | grep -E '^[0-9]+$' | head -n 1 || true)
    if [[ -n "${PARSED_RUN_ID}" ]]; then
      RUN_ID="${PARSED_RUN_ID}"
      break
    fi
  else
    LAST_GH_ERR="${OUTPUT}"
  fi
  sleep "${POLL_INTERVAL_CI}"
done

if [[ -z "${RUN_ID}" ]]; then
  echo "Error: CI run for commit ${COMMIT_SHA} on branch ${BRANCH} not found within deadline." >&2
  if [[ -n "${LAST_GH_ERR}" ]]; then
    echo "Last GitHub API error: ${LAST_GH_ERR}" >&2
  fi
  exit 1
fi

echo "Found CI run ${RUN_ID}. Monitoring execution..."
if ! gh run watch "${RUN_ID}" --exit-status; then
  echo "Error: CI run ${RUN_ID} failed or was cancelled." >&2
  gh run view "${RUN_ID}" --log-failed >&2 || true
  exit 1
fi

echo "CI run ${RUN_ID} completed successfully."
echo "Remote delivery and CI verification successful for commit ${COMMIT_SHA}."
exit 0
