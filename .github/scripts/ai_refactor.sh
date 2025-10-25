#!/usr/bin/env bash
# File: .github/scripts/ai_refactor.sh
# Purpose: Run safe auto-fixes and (when necessary) call OpenRouter to produce an AI patch,
# validate it, commit only allowed files, push branch to origin (using GH2_TOKEN), and output pr_branch.
# Drop-in replacement (latest, robust, self-healing).
set -euo pipefail

# ---------------------------
# Usage and arguments
# ---------------------------
ARTIFACTS_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$ARTIFACTS_DIR" ]; then
  echo "Usage: $0 --artifacts <path-to-artifacts>" >&2
  exit 1
fi

# ---------------------------
# Environment checks
# ---------------------------
WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
ART_DIR="${WORKDIR}/${ARTIFACTS_DIR}"
mkdir -p "$ART_DIR"

# Required secrets / env
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set (repo secret)}"
: "${GH2_TOKEN:?GH2_TOKEN must be set (repo secret)}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set (env provided by Actions)}"

cd "$WORKDIR"

# Mark workspace as safe for git
git config --global --add safe.directory "$WORKDIR" || true

# Ensure origin remote authenticated with GH2_TOKEN to avoid ambiguous-origin issues
# actions/checkout in workflow ideally already set this, but do a safe set-url here to guarantee
git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" 2>/dev/null || true
git fetch origin --prune --tags || true

# Files we allow changes for and commit
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

# Diagnostics / artifact paths
DIAG="${ART_DIR}/ai-diagnostics.txt"
AI_RAW="${ART_DIR}/ai-raw-response.json"
AI_RESP="${ART_DIR}/ai-response.txt"
PATCH_BEFORE="${ART_DIR}/ai-diff-before.patch"
PATCH_AFTER="${ART_DIR}/ai-diff-after.patch"
VALIDATE_LOG="${ART_DIR}/ai-validate.log"

# Save before-diff
git diff -- "${TARGET_FILES[@]}" > "${PATCH_BEFORE}" 2>/dev/null || true

# Header for diagnostics
{
  echo "ai_refactor.sh diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY}"
  echo "workspace: ${WORKDIR}"
  echo
} > "$DIAG"

# ---------------------------
# Ensure helper tools available (jq, goimports)
# ---------------------------
# Try to install jq if missing (best-effort; only on linux runners where apt-get exists)
if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y jq >/dev/null 2>&1 || true
  fi
fi

# Ensure go is available
if ! command -v go >/dev/null 2>&1; then
  echo "go command is not available in PATH. Exiting." >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Ensure GOBIN is set or fallback
GOBIN="${GOBIN:-$HOME/go/bin}"
mkdir -p "$GOBIN"
export GOBIN
# Ensure GOBIN on PATH
if ! echo "$PATH" | tr ':' '\n' | grep -Fqx "$GOBIN"; then
  export PATH="$GOBIN:$PATH"
fi

# Install goimports if missing (self-heal)
if ! command -v goimports >/dev/null 2>&1; then
  echo "goimports not found; installing to ${GOBIN}" >> "$DIAG"
  # go install writes to GOBIN (Go 1.17+ behaviour)
  GO_PKG="golang.org/x/tools/cmd/goimports@latest"
  if go install "$GO_PKG" >/dev/null 2>&1; then
    echo "goimports installed" >> "$DIAG"
    export PATH="$GOBIN:$PATH"
  else
    echo "goimports install failed" >> "$DIAG"
  fi
fi

# Ensure golangci-lint exists; if not, we continue (workflow may install it)
if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "golangci-lint not found; some auto-fixes will be skipped" >> "$DIAG"
fi

# ---------------------------
# Safe automatic fixes
# ---------------------------
{
  echo "Running safe automatic fixes..." >> "$DIAG"
  # format
  gofmt -s -w . || true
  # try goimports (if installed)
  if command -v goimports >/dev/null 2>&1; then
    goimports -w . || true
  fi
  # try golangci-lint --fix if available
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=10m ./... >> "${ART_DIR}/golangci-fix.log" 2>&1 || true
  fi
  # tidy modules
  go mod tidy >> "${ART_DIR}/go-mod-tidy.log" 2>&1 || true
} || true

# If safe fixes changed target files, commit & push branch and exit
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
    BRANCH="ai/auto-fix-${TIMESTAMP}"
    git checkout -b "${BRANCH}"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    # stage only the allowed files
    for f in "${TARGET_FILES[@]}"; do
      if [ -f "$f" ]; then
        git add -- "$f" || true
      fi
    done
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    if git push --set-upstream origin "${BRANCH}" >/dev/null 2>&1; then
      echo "Safe-fix branch pushed: ${BRANCH}" >> "$DIAG"
      git diff origin/main.."${BRANCH}" > "${PATCH_AFTER}" 2>/dev/null || true
      echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
      exit 0
    else
      echo "Failed to push safe-fix branch ${BRANCH}" >> "$DIAG"
      echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
      exit 0
    fi
  fi
done

# ---------------------------
# No safe auto-fix changes: collect diagnostics for AI
# ---------------------------
# Run golangci-lint full run if available, capture JSON and stderr
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --out-format json ./... > "${ART_DIR}/golangci.runtime.json" 2> "${ART_DIR}/golangci.runtime.stderr" || true
fi

# Build & test outputs
go build ./... > "${ART_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ART_DIR}/go-test-output.txt" 2>&1 || true

# Decide whether AI needed: build/test fail or lint issues affecting target files
NEED_AI=false
if [ -s "${ART_DIR}/go-build-output.txt" ] || [ -s "${ART_DIR}/go-test-output.txt" ]; then
  NEED_AI=true
fi
if [ -f "${ART_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  # check if any lint issues mention our target files
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ART_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|%s|%s' "${TARGET_FILES[0]}" "${TARGET_FILES[1]}" "${TARGET_FILES[2]}")" >/dev/null 2>&1; then
    NEED_AI=true
  fi
fi

if [ "$NEED_AI" = false ]; then
  echo "No relevant issues found; nothing for AI to fix." >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------------------------
# Build concise AI prompt (bounded)
# ---------------------------
PROMPT_FILE="$(mktemp)"
{
  echo "You are an expert Go maintainer. Produce a single unified git patch (diff) enclosed in triple backticks ``` that fixes the lint/build/test issues below."
  echo "Only modify these files if necessary: ${TARGET_FILES[*]}. Keep changes minimal and safe; preserve behaviour unless a change is necessary to fix an error. If you update go.mod, prefer minimal version bumps and run 'go mod tidy'."
  echo
  echo "=== LINT (truncated) ==="
  if [ -f "${ART_DIR}/golangci.runtime.stderr" ]; then
    sed -n '1,200p' "${ART_DIR}/golangci.runtime.stderr"
  fi
  echo
  echo "=== BUILD (truncated) ==="
  sed -n '1,200p' "${ART_DIR}/go-build-output.txt" || true
  echo
  echo "=== TEST (truncated) ==="
  sed -n '1,200p' "${ART_DIR}/go-test-output.txt" || true
  echo
  echo "==== FILES (full) ==="
  for f in "${TARGET_FILES[@]}"; do
    if [ -f "$f" ]; then
      echo "----- FILE: $f -----"
      sed -n '1,200p' "$f" || true
      echo
    fi
  done
} > "$PROMPT_FILE"

# ---------------------------
# Call OpenRouter (Chat Completions)
# ---------------------------
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="minimax/minimax-m2:free"

# Prepare JSON payload (use jq if available, otherwise heredoc)
if command -v jq >/dev/null 2>&1; then
  PAYLOAD=$( jq -n \
    --arg model "$MODEL" \
    --arg sys "You are an expert Go code patch generator. Provide exactly one fenced diff patch." \
    --arg usr "$(sed -n '1,20000p' "$PROMPT_FILE")" \
    '{
      model: $model,
      messages: [
        {role:"system", content:$sys},
        {role:"user", content:$usr}
      ],
      temperature: 0.0,
      max_tokens: 32768
    }' )
else
  # Fallback: simple payload (less safe if PROMPT_FILE contains quotes/newlines)
  PAYLOAD=$(cat <<EOF
{"model":"${MODEL}","messages":[{"role":"system","content":"You are an expert Go code patch generator. Provide exactly one fenced diff patch."},{"role":"user","content":"$(sed -n '1,20000p' "$PROMPT_FILE" | sed 's/"/\\"/g' | tr '\n' '\\u2028')"}],"temperature":0.0,"max_tokens":32768}
EOF
)
fi

# Call API
RESPONSE_TMP="$(mktemp)"
HTTP_CODE=$(curl -sS -X POST "$API_URL" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" -w "%{http_code}" -o "$RESPONSE_TMP" )

# Save raw response
cp "$RESPONSE_TMP" "$AI_RAW" || true

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "OpenRouter API returned HTTP $HTTP_CODE" >> "$DIAG"
  cat "$RESPONSE_TMP" >> "$DIAG" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Extract AI content (require jq)
if command -v jq >/dev/null 2>&1; then
  AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // empty' "$RESPONSE_TMP" 2>/dev/null || true)
else
  AI_CONTENT=$(sed -n '1,20000p' "$RESPONSE_TMP")
fi
echo "$AI_CONTENT" > "$AI_RESP"

# ---------------------------
# Extract and apply patch
# ---------------------------
PATCH_TMP="$(mktemp)"
if echo "$AI_CONTENT" | grep -q '```'; then
  # Extract content between the first fenced block
  echo "$AI_CONTENT" | sed -n '/```/,/```/p' | sed '1d;$d' > "$PATCH_TMP" || true
else
  echo "No fenced patch found in AI response" >> "$DIAG"
  echo "AI response saved to ${AI_RAW}" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate patch applies cleanly
if ! git apply --check "$PATCH_TMP" > /tmp/ai_patch_check.out 2>&1; then
  echo "AI patch failed git apply --check" >> "$DIAG"
  cat /tmp/ai_patch_check.out >> "$DIAG" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Apply the patch
git apply "$PATCH_TMP" || {
  echo "git apply failed" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
}

# ---------------------------
# Validate after applying patch (build/test/lint)
# ---------------------------
{
  echo "Validating after AI patch..." >> "$VALIDATE_LOG"
  set +e
  go mod tidy >> "$VALIDATE_LOG" 2>&1 || true
  go build ./... >> "$VALIDATE_LOG" 2>&1
  build_exit=$?
  go test ./... >> "$VALIDATE_LOG" 2>&1
  test_exit=$?
  set -e
  echo "build_exit=${build_exit}, test_exit=${test_exit}" >> "$VALIDATE_LOG"
} || true

if [ "${build_exit:-1}" -ne 0 ] || [ "${test_exit:-1}" -ne 0 ]; then
  echo "Validation (build/test) failed after AI patch. Reverting changes." >> "$DIAG"
  git checkout -- . || true
  cp "$VALIDATE_LOG" "${ART_DIR}/ai-validate.log" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------------------------
# Commit & push only allowed files
# ---------------------------
# Determine changed target files
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=("$tf")
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch did not change any of the allowed target files; aborting." >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/ai-fix-${TIMESTAMP}"
git checkout -b "$BRANCH"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
git config user.name "github-actions[bot]" || true

for f in "${CHANGED_TARGETS[@]}"; do
  git add -- "$f" || true
done
# Also ensure go.mod/go.sum are included if changed (they may already be in CHANGED_TARGETS)
for f in go.mod go.sum; do
  if git status --porcelain | awk '{print $2}' | grep -Fqx "$f"; then
    git add -- "$f" || true
  fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true

# Push branch to origin (authenticated via GH2_TOKEN set earlier)
if git push --set-upstream origin "$BRANCH" >/dev/null 2>&1; then
  echo "Branch pushed: $BRANCH" >> "$DIAG"
  git diff origin/main.."${BRANCH}" > "${PATCH_AFTER}" 2>/dev/null || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  cp "$VALIDATE_LOG" "${ART_DIR}/ai-validate.log" || true
  echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
  exit 0
else
  echo "Failed to push branch $BRANCH" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi
