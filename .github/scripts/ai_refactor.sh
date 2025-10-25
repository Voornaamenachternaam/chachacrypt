#!/usr/bin/env bash
# =====================================================================
# AI Refactor Script for ChachaCrypt
# Automatically fixes lint/build/test issues using golangci-lint, goimports,
# and AI-based code improvements via OpenRouter.
# =====================================================================

set -euo pipefail

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
REPO_DIR="${GITHUB_WORKSPACE:-$(pwd)}"
ARTIFACT_DIR="${1:-ci-artifacts}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
MODEL="openai/gpt-4o-mini"
AI_PROMPT_FILE="$ARTIFACT_DIR/ai_prompt.txt"
AI_RESPONSE_FILE="$ARTIFACT_DIR/ai_response.txt"
LOG_FILE="$ARTIFACT_DIR/ai_refactor.log"

mkdir -p "$ARTIFACT_DIR"

echo "[INFO] Starting AI refactor process in: $REPO_DIR" | tee "$LOG_FILE"

# ---------------------------------------------------------------------
# Ensure Go tools are available
# ---------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  echo "[ERROR] Go not found. Exiting." | tee -a "$LOG_FILE"
  exit 1
fi

if ! command -v goimports >/dev/null 2>&1; then
  echo "[INFO] Installing goimports..." | tee -a "$LOG_FILE"
  go install golang.org/x/tools/cmd/goimports@latest
fi

if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "[INFO] Installing golangci-lint v2.5.0..." | tee -a "$LOG_FILE"
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$(go env GOPATH)/bin" v2.5.0
fi

export PATH="$(go env GOPATH)/bin:$PATH"

# ---------------------------------------------------------------------
# Step 1. Run goimports and golangci-lint
# ---------------------------------------------------------------------
echo "[INFO] Running goimports formatting..." | tee -a "$LOG_FILE"
goimports -w .

echo "[INFO] Running golangci-lint..." | tee -a "$LOG_FILE"
if ! golangci-lint run --fix --timeout=5m; then
  echo "[WARN] golangci-lint found issues; attempting fixes..." | tee -a "$LOG_FILE"
fi

# ---------------------------------------------------------------------
# Step 2. Run go build and go test, capturing any errors
# ---------------------------------------------------------------------
BUILD_LOG="$ARTIFACT_DIR/go_build.log"
TEST_LOG="$ARTIFACT_DIR/go_test.log"
LINT_LOG="$ARTIFACT_DIR/golangci-lint.log"

{
  go build ./... 2>&1 || true
  go test ./... 2>&1 || true
} | tee "$BUILD_LOG"

golangci-lint run 2>&1 | tee "$LINT_LOG" || true
go test ./... 2>&1 | tee "$TEST_LOG" || true

# Collect all errors
ERRORS="$(grep -E 'error|FAIL' "$BUILD_LOG" "$TEST_LOG" "$LINT_LOG" || true)"

if [[ -z "$ERRORS" ]]; then
  echo "[INFO] No build/test/lint errors detected. AI step skipped." | tee -a "$LOG_FILE"
  exit 0
fi

# ---------------------------------------------------------------------
# Step 3. Prepare AI prompt
# ---------------------------------------------------------------------
echo "[INFO] Preparing AI prompt..." | tee -a "$LOG_FILE"

cat >"$AI_PROMPT_FILE" <<EOF
You are an expert Go engineer. Analyze and fix all build, lint, and test issues in the following project.
Apply idiomatic and modern Go best practices.
Preserve functionality, improve readability, and ensure full test passing.
Provide corrected Go source code only — no commentary or markdown formatting.

Errors to fix:
$ERRORS

Affected files: chachacrypt.go, go.mod, go.sum (and related files if needed)
EOF

# ---------------------------------------------------------------------
# Step 4. Send prompt to OpenRouter
# ---------------------------------------------------------------------
if [[ -z "$OPENROUTER_API_KEY" ]]; then
  echo "[ERROR] Missing OPENROUTER_API_KEY" | tee -a "$LOG_FILE"
  exit 1
fi

echo "[INFO] Sending request to OpenRouter ($MODEL)..." | tee -a "$LOG_FILE"

AI_CONTENT=""
AI_CONTENT=$(curl -sS -X POST "https://openrouter.ai/api/v1/chat/completions" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"model\": \"${MODEL}\",
    \"messages\": [
      {\"role\": \"system\", \"content\": \"You are a senior Go refactoring assistant.\"},
      {\"role\": \"user\", \"content\": $(jq -Rs . < \"$AI_PROMPT_FILE\")}
    ],
    \"temperature\": 0.4
  }" \
  | jq -r '.choices[0].message.content // empty' || true)

if [[ -z "$AI_CONTENT" ]]; then
  echo "[ERROR] AI did not return content." | tee -a "$LOG_FILE"
  exit 1
fi

echo "$AI_CONTENT" > "$AI_RESPONSE_FILE"
echo "[INFO] AI response saved to $AI_RESPONSE_FILE" | tee -a "$LOG_FILE"

# ---------------------------------------------------------------------
# Step 5. Apply AI modifications
# ---------------------------------------------------------------------
echo "[INFO] Applying AI-generated code changes..." | tee -a "$LOG_FILE"

# Backup before applying
cp chachacrypt.go "$ARTIFACT_DIR/chachacrypt.go.bak" || true

# Write the AI's refactored code (if clearly Go code)
if grep -q "package " "$AI_RESPONSE_FILE"; then
  echo "$AI_CONTENT" > chachacrypt.go
  echo "[INFO] AI modifications written to chachacrypt.go" | tee -a "$LOG_FILE"
else
  echo "[WARN] AI output not detected as Go code. Skipping overwrite." | tee -a "$LOG_FILE"
fi

# ---------------------------------------------------------------------
# Step 6. Verify and finalize
# ---------------------------------------------------------------------
echo "[INFO] Rebuilding and testing after AI refactor..." | tee -a "$LOG_FILE"
if ! go build ./...; then
  echo "[WARN] Build still failing post-AI. Keeping logs." | tee -a "$LOG_FILE"
else
  echo "[SUCCESS] Build passed after AI refactor." | tee -a "$LOG_FILE"
fi

go test ./... -v | tee -a "$LOG_FILE" || true

echo "[INFO] AI refactor completed successfully." | tee -a "$LOG_FILE"
exit 0
