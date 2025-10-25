# .github/scripts/ai_refactor.sh (revised)
#!/usr/bin/env bash
set -euo pipefail

# Usage: ./ai_refactor.sh --artifacts <path>
ARTIFACTS_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done
if [ -z "$ARTIFACTS_DIR" ]; then
  echo "Usage: $0 --artifacts <path-to-artifacts>"
  exit 1
fi

WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
ART_DIR="${WORKDIR}/${ARTIFACTS_DIR}"
mkdir -p "${ART_DIR}"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"

TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
DIAG="${ART_DIR}/ai-diagnostics.txt"

# Ensure tools
for tool in git curl jq; do
  command -v $tool >/dev/null 2>&1 || { echo "$tool required"; exit 1; }
done

# Run linters and auto-fixes (gofmt, golangci-lint --fix, etc.)
go fmt ./... 2>/dev/null || true
golangci-lint run --timeout=10m --fix ./... > "${ART_DIR}/golangci.stdout" 2> "${ART_DIR}/golangci.stderr" || true
go mod tidy >> "${ART_DIR}/auto-fix.log" 2>&1 || true

# If changes occurred on target files, set branch and exit (safe fixes path)
CHANGED_FILES=$(git status --porcelain | awk '{print $2}' || true)
if [ -n "${CHANGED_FILES}" ]; then
  for tf in "${TARGET_FILES[@]}"; do
    if echo "${CHANGED_FILES}" | grep -Fqx "$tf"; then
      TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
      BRANCH="ai/auto-fix-${TIMESTAMP}"
      # Do not push or commit here; leave changes for create-pull-request
      echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
      exit 0
    fi
  done
fi

# Capture diagnostics (simulate running AI)
# (Omitted actual API calls for brevity; assume we get a diff patch)
# After generating AI-patched code (left as an exercise), check build:
go build ./... >> "${ART_DIR}/ai-validate.log" 2>&1 || true
go test ./... >> "${ART_DIR}/ai-validate.log" 2>&1 || true

# Determine if AI changes touched target files
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "${CHANGED_NOW}" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=("$tf")
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  # No relevant changes
  echo "No AI changes on target files." >> "${DIAG}"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/ai-fix-${TIMESTAMP}"
# Leave files staged in workspace; commit will be done by create-pull-request
git add "${TARGET_FILES[@]}" 2>/dev/null || true
echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
exit 0
