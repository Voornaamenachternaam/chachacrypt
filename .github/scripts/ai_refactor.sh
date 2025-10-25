#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Drop-in replacement (robust, self-healing, forces bash runtime)
set -euo pipefail

# If not running under bash, re-exec with bash so bash features (arrays, [[, etc.) work.
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi

# ---------------------------
# Usage and args
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
# Environment checks / setup
# ---------------------------
WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
ART_DIR="${WORKDIR}/${ARTIFACTS_DIR}"
mkdir -p "$ART_DIR"

# Required secrets/env
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set (repo secret)}"
: "${GH2_TOKEN:?GH2_TOKEN must be set (repo secret)}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

cd "$WORKDIR"

# Mark workspace safe for git
git config --global --add safe.directory "$WORKDIR" >/dev/null 2>&1 || true

# Ensure origin remote authenticated with GH2_TOKEN to avoid ambiguous-origin issues
# actions/checkout in the workflow normally sets this; set-url here as a safe fallback
git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" >/dev/null 2>&1 || true
git fetch origin --prune --tags >/dev/null 2>&1 || true

# ---------------------------
# Constants / artifacts
# ---------------------------
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

DIAG="${ART_DIR}/ai-diagnostics.txt"
AI_RAW="${ART_DIR}/ai-raw-response.json"
AI_RESP="${ART_DIR}/ai-response.txt"
PATCH_BEFORE="${ART_DIR}/ai-diff-before.patch"
PATCH_AFTER="${ART_DIR}/ai-diff-after.patch"
VALIDATE_LOG="${ART_DIR}/ai-validate.log"

# Write header to diagnostics
{
  echo "ai_refactor.sh diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY}"
  echo "workspace: ${WORKDIR}"
  echo
} > "$DIAG"

# Save before-diff of target files
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# ---------------------------
# Ensure helper tools (jq, goimports)
# ---------------------------
# try to ensure jq exists (best-effort)
if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y jq >/dev/null 2>&1 || true
  fi
fi

# Ensure go is available
if ! command -v go >/dev/null 2>&1; then
  echo "go command not available; aborting." >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Ensure GOBIN exists and is on PATH
GOBIN="${GOBIN:-$HOME/go/bin}"
mkdir -p "$GOBIN"
export GOBIN
case ":$PATH:" in
  *":$GOBIN:"*) ;;
  *) PATH="$GOBIN:$PATH" ;;
esac

# Install goimports if missing (self-heal)
if ! command -v goimports >/dev/null 2>&1; then
  echo "goimports not found; attempting to install to ${GOBIN}" >> "$DIAG"
  if go install golang.org/x/tools/cmd/goimports@latest >/dev/null 2>&1; then
    echo "goimports installed" >> "$DIAG"
    PATH="$GOBIN:$PATH"
  else
    echo "goimports install failed; continuing (gofmt will still run)" >> "$DIAG"
  fi
fi

# Note if golangci-lint missing (workflow usually installs it)
if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "golangci-lint not found; some auto-fixes (--fix) will be skipped" >> "$DIAG"
fi

# ---------------------------
# Safe automatic fixes (non-AI)
# ---------------------------
{
  echo "Running safe auto-fixes..." >> "$DIAG"
  # format whole repo
  gofmt -s -w . || true
  # goimports if available
  if command -v goimports >/dev/null 2>&1; then
    goimports -w . || true
  fi
  # golangci-lint --fix if available
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=10m ./... >> "${ART_DIR}/golangci-fix.log" 2>&1 || true
  fi
  # go mod tidy
  go mod tidy >> "${ART_DIR}/go-mod-tidy.log" 2>&1 || true
} || true

# If safe fixes changed any target file, commit & push branch and exit
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
    BRANCH="ai/auto-fix-${TIMESTAMP}"
    git checkout -b "$BRANCH"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    # stage only allowed files
    for f in "${TARGET_FILES[@]}"; do
      [ -f "$f" ] && git add -- "$f" || true
    done
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    if git push --set-upstream origin "$BRANCH" >/dev/null 2>&1; then
      echo "Safe-fix branch pushed: $BRANCH" >> "$DIAG"
      git diff origin/main.."${BRANCH}" > "$PATCH_AFTER" 2>/dev/null || true
      cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
      echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
      exit 0
    else
      echo "Failed to push safe-fix branch $BRANCH" >> "$DIAG"
      cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
      echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
      exit 0
    fi
  fi
done

# ---------------------------
# No safe fixes: collect diagnostics for AI
# ---------------------------
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --out-format json ./... > "${ART_DIR}/golangci.runtime.json" 2> "${ART_DIR}/golangci.runtime.stderr" || true
fi

go build ./... > "${ART_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ART_DIR}/go-test-output.txt" 2>&1 || true

NEED_AI=false
if [ -s "${ART_DIR}/go-build-output.txt" ] || [ -s "${ART_DIR}/go-test-output.txt" ]; then
  NEED_AI=true
fi
if [ -f "${ART_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ART_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|%s|%s' "${TARGET_FILES[0]}" "${TARGET_FILES[1]}" "${TARGET_FILES[2]}")" >/dev/null 2>&1; then
    NEED_AI=true
  fi
fi

if [ "$NEED_AI" = false ]; then
  echo "No AI-needed issues; exiting." >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------------------------
# Build AI prompt (concise)
# ---------------------------
PROMPT_FILE=$(mktemp)
{
  echo "You are an expert Go maintainer. Produce a single unified git diff patch (fenced with ``` ) that fixes the lint/build/test issues below."
  echo "Only modify these files if necessary: ${TARGET_FILES[*]}. Keep changes minimal and safe; preserve behavior unless a change is required to fix an error."
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
  echo "=== FILES (first 200 lines each) ==="
  for f in "${TARGET_FILES[@]}"; do
    if [ -f "$f" ]; then
      echo "----- FILE: $f -----"
      sed -n '1,200p' "$f" || true
      echo
    fi
  done
} > "$PROMPT_FILE"

# ---------------------------
# Call OpenRouter Chat Completions
# ---------------------------
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="minimax/minimax-m2:free"

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
  # Fallback payload (best-effort)
  PAYLOAD=$(printf '{"model":"%s","messages":[{"role":"system","content":"You are an expert Go code patch generator. Provide exactly one fenced diff patch."},{"role":"user","content":"%s"}],"temperature":0.0,"max_tokens":32768}' \
    "$MODEL" "$(sed -n '1,20000p' "$PROMPT_FILE" | sed 's/"/\\"/g' | tr '\n' '\\u2028')")
fi

RESPONSE_TMP=$(mktemp)
HTTP_CODE=$(curl -sS -X POST "$API_URL" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" -w "%{http_code}" -o "$RESPONSE_TMP" )

cp "$RESPONSE_TMP" "$AI_RAW" || true

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "OpenRouter API returned HTTP $HTTP_CODE" >> "$DIAG"
  cat "$RESPONSE_TMP" >> "$DIAG" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Extract AI content (prefer jq)
if command -v jq >/dev/null 2>&1; then
  AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // empty' "$RESPONSE_TMP" 2>/dev/null || true)
else
  AI_CONTENT=$(sed -n '1,20000p' "$RESPONSE_TMP")
fi
echo "$AI_CONTENT" > "$AI_RESP"

# ---------------------------
# Extract patch and apply
# ---------------------------
PATCH_TMP=$(mktemp)
if echo "$AI_CONTENT" | grep -q '```'; then
  # extract first fenced block
  echo "$AI_CONTENT" | sed -n '/```/,/```/p' | sed '1d;$d' > "$PATCH_TMP" || true
else
  echo "No fenced patch in AI response" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate patch can apply
if ! git apply --check "$PATCH_TMP" > /tmp/ai_patch_check.out 2>&1; then
  echo "AI patch failed git apply --check" >> "$DIAG"
  cat /tmp/ai_patch_check.out >> "$DIAG" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

git apply "$PATCH_TMP" || {
  echo "git apply failed" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
}

# ---------------------------
# Validate after patch (build/test)
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
  echo "Validation failed after AI patch. Reverting changes." >> "$DIAG"
  git checkout -- . || true
  cp "$VALIDATE_LOG" "${ART_DIR}/ai-validate.log" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------------------------
# Commit & push only allowed files
# ---------------------------
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=("$tf")
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch did not change any allowed target files; aborting." >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/ai-fix-${TIMESTAMP}"
git checkout -b "$BRANCH"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
git config user.name "github-actions[bot]" || true

# Stage only changed allowed files (and go.mod/go.sum if changed)
for f in "${CHANGED_TARGETS[@]}"; do
  git add -- "$f" || true
done
for f in go.mod go.sum; do
  if git status --porcelain | awk '{print $2}' | grep -Fqx "$f"; then
    git add -- "$f" || true
  fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true

if git push --set-upstream origin "$BRANCH" >/dev/null 2>&1; then
  echo "Branch pushed: $BRANCH" >> "$DIAG"
  git diff origin/main.."${BRANCH}" > "$PATCH_AFTER" 2>/dev/null || true
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
