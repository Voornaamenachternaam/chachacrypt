#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
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

# Environment checks
WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
ART_DIR="${WORKDIR}/${ARTIFACTS_DIR}"
mkdir -p "${ART_DIR}"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set (GitHub secret)}"
: "${GH2_TOKEN:?GH2_TOKEN must be set (GitHub secret)}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

cd "${WORKDIR}"
# ensure safe dir
git config --global --add safe.directory "${WORKDIR}" || true

# Make sure origin is configured with the same GH2_TOKEN so pushes are visible on origin.
# actions/checkout in the workflow already sets token, but this is a safe fallback:
git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" || true
git fetch origin --prune --tags || true

# Files we allow AI or fixes to touch
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

# Save a pre-change diff for diagnostics
git diff -- "${TARGET_FILES[@]}" > "${ART_DIR}/ai-diff-before.patch" 2>/dev/null || true

# Basic diagnostics header
{
  echo "AI diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "Repo: ${GITHUB_REPOSITORY}"
  echo "Workspace: ${WORKDIR}"
} > "${ART_DIR}/ai-diagnostics.txt"

# Install basic helpers if missing (jq, goimports) on ubuntu runner if necessary
if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y || true
    sudo apt-get install -y jq || true
  fi
fi
if ! command -v goimports >/dev/null 2>&1; then
  if command -v go >/dev/null 2>&1; then
    go install golang.org/x/tools/cmd/goimports@latest || true
  fi
fi

# Apply safe automatic fixes
{
  echo "Running safe auto-fixes..." >> "${ART_DIR}/ai-diagnostics.txt"
  gofmt -s -w . || true
  if command -v goimports >/dev/null 2>&1; then
    goimports -w . || true
  fi
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=10m ./... >> "${ART_DIR}/golangci-fix.log" 2>&1 || true
  fi
  go mod tidy >> "${ART_DIR}/go-mod-tidy.log" 2>&1 || true
} || true

# Check git status for changes to allowed files
CHANGED_FILES=$(git status --porcelain | awk '{print $2}' || true)

for tf in "${TARGET_FILES[@]}"; do
  if echo "${CHANGED_FILES}" | grep -Fqx "$tf"; then
    # commit and push a branch with safe fixes
    TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
    BRANCH="ai/auto-fix-${TIMESTAMP}"
    git checkout -b "${BRANCH}"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    # stage only target files (to avoid artifacts)
    for f in "${TARGET_FILES[@]}"; do
      if [ -f "$f" ]; then
        git add -- "$f" || true
      fi
    done
    # include go.sum/go.mod too if changed
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix) for target files" || true
    git push --set-upstream origin "${BRANCH}" || true
    echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
    git diff origin/main.."${BRANCH}" > "${ART_DIR}/ai-diff-after.patch" 2>/dev/null || true
    exit 0
  fi
done

# No safe auto-fix changes. Collect diagnostics (lint/build/test) to feed the AI.
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --out-format json ./... > "${ART_DIR}/golangci.runtime.json" 2> "${ART_DIR}/golangci.runtime.stderr" || true
else
  echo "golangci-lint not installed" >> "${ART_DIR}/ai-diagnostics.txt"
fi

go build ./... > "${ART_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ART_DIR}/go-test-output.txt" 2>&1 || true

# Determine whether issues touch target files or build/test failed
relevant=false
if [ -s "${ART_DIR}/go-build-output.txt" ] || [ -s "${ART_DIR}/go-test-output.txt" ]; then
  relevant=true
fi
if [ -f "${ART_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ART_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|' "${TARGET_FILES[@]}" | sed 's/|$//')" >/dev/null 2>&1; then
    relevant=true
  fi
fi

if [ "${relevant}" != "true" ]; then
  echo "No relevant issues found; nothing for AI to fix." >> "${ART_DIR}/ai-diagnostics.txt"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Build AI prompt (trimmed, but include relevant sections)
PROMPT_FILE="$(mktemp)"
{
  echo "You are an expert Go maintainer and security-conscious code refactorer."
  echo "Produce a single unified git patch (git format-patch unified/diff) enclosed in triple backticks."
  echo "Only modify these files if necessary: ${TARGET_FILES[*]}"
  echo
  echo "Goals:"
  echo "1) Fix all lint, build, and test issues affecting the listed files."
  echo "2) Prefer minimal, safe modernizations; keep behavior identical unless necessary to fix an error."
  echo "3) Update go.mod/go.sum minimally and run 'go mod tidy' afterwards."
  echo
  echo "Provide only the patch (fenced with ```), plus a short changelog line above the patch (one line)."
  echo
  echo "=== Linter output (truncated) ==="
  if [ -f "${ART_DIR}/golangci.runtime.json" ]; then
    jq -r '.Issues[]? | "\(.FromLinter) | \(.Pos.Filename):\(.Pos.Line) | \(.Text)"' "${ART_DIR}/golangci.runtime.json" | sed -n '1,200p'
  else
    sed -n '1,200p' "${ART_DIR}/golangci.runtime.stderr" || true
  fi
  echo
  echo "=== Build output (truncated) ==="
  sed -n '1,200p' "${ART_DIR}/go-build-output.txt" || true
  echo
  echo "=== Test output (truncated) ==="
  sed -n '1,200p' "${ART_DIR}/go-test-output.txt" || true
  echo
  echo "=== File snippets (context) for target files (±6 lines) ==="
  for f in "${TARGET_FILES[@]}"; do
    if [ -f "$f" ]; then
      echo "<<< FILE: $f >>>"
      nl -ba -w3 -s': ' "$f" | sed -n '1,200p'
      echo "<<< END FILE: $f >>>"
      echo
    fi
  done
} > "${PROMPT_FILE}"

# Call OpenRouter (Chat Completions)
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="minimax/minimax-m2:free"

PAYLOAD=$( jq -n \
  --arg model "$MODEL" \
  --arg system "You are a terse expert assistant for producing a single git patch that fixes the reported issues." \
  --arg user "$(sed -n '1,20000p' "${PROMPT_FILE}")" \
  '{
    model: $model,
    messages: [
      {role:"system", content:$system},
      {role:"user", content:$user}
    ],
    temperature: 0.0,
    max_tokens: 32768
  }' )

RESPONSE_TMP="$(mktemp)"
HTTP_CODE=$(curl -sS -X POST "$API_URL" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" -w "%{http_code}" -o "$RESPONSE_TMP")

cp "$RESPONSE_TMP" "${ART_DIR}/ai-raw-response.json" || true

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "OpenRouter API returned HTTP ${HTTP_CODE}" >> "${ART_DIR}/ai-diagnostics.txt"
  cat "$RESPONSE_TMP" >> "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // ""' "$RESPONSE_TMP" 2>/dev/null || true)
echo "$AI_CONTENT" > "${ART_DIR}/ai-response.txt"

# Extract diff from AI content
PATCH_TMP="$(mktemp)"
if grep -q '```diff' "${ART_DIR}/ai-response.txt"; then
  sed -n '/```diff/,/```/p' "${ART_DIR}/ai-response.txt" | sed '1d;$d' > "${PATCH_TMP}" || true
elif grep -q '```' "${ART_DIR}/ai-response.txt"; then
  sed -n '/```/,/```/p' "${ART_DIR}/ai-response.txt" | sed '1d;$d' > "${PATCH_TMP}" || true
else
  echo "No fenced patch found in AI response" >> "${ART_DIR}/ai-diagnostics.txt"
  echo "AI response saved to ${ART_DIR}/ai-response.txt" >> "${ART_DIR}/ai-diagnostics.txt"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate patch can apply
if ! git apply --check "${PATCH_TMP}" > /tmp/ai_patch_check.out 2>&1; then
  echo "AI patch failed git apply --check" >> "${ART_DIR}/ai-diagnostics.txt"
  cat /tmp/ai_patch_check.out >> "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Apply patch
git apply "${PATCH_TMP}" || { echo "git apply failed" >> "${ART_DIR}/ai-diagnostics.txt"; echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="; exit 0; }

# Validate after patch (go build/test and lint)
set +e
go mod tidy >> "${ART_DIR}/ai-validate.log" 2>&1 || true
go build ./... >> "${ART_DIR}/ai-validate.log" 2>&1
build_exit=$?
go test ./... >> "${ART_DIR}/ai-validate.log" 2>&1
test_exit=$?
set -e

if [ $build_exit -ne 0 ] || [ $test_exit -ne 0 ]; then
  echo "Validation failed after AI patch (build or test). Build exit: ${build_exit}, test exit: ${test_exit}" >> "${ART_DIR}/ai-diagnostics.txt"
  echo "Reverting applied patch." >> "${ART_DIR}/ai-diagnostics.txt"
  git checkout -- . || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Determine changed target files and commit only allowed files
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "${CHANGED_NOW}" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=("$tf")
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch did not change any of the target files. No PR will be created." >> "${ART_DIR}/ai-diagnostics.txt"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/ai-fix-${TIMESTAMP}"
git checkout -b "${BRANCH}"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
git config user.name "github-actions[bot]" || true

# Stage only changed target files
for f in "${CHANGED_TARGETS[@]}"; do
  git add -- "$f" || true
done
# Also add go.mod & go.sum if present and changed
for f in go.mod go.sum; do
  if git status --porcelain | awk '{print $2}' | grep -Fqx "$f"; then
    git add -- "$f" || true
  fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true
git push --set-upstream origin "${BRANCH}" || true

# Save after-diff
git diff origin/main.."${BRANCH}" > "${ART_DIR}/ai-diff-after.patch" 2>/dev/null || true
echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
exit 0
