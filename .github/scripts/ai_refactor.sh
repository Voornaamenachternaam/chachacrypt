#!/usr/bin/env bash
# =====================================================================
# AI Refactor Script for ChachaCrypt
# Author: Automated CI Assistant
# Purpose: Automatically detect, fix, and refactor Go code using:
#  - goimports
#  - golangci-lint
#  - OpenRouter AI model (DeepSeek-Coder / the required model)
# =====================================================================

set -euo pipefail

# ---------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------
ARTIFACT_DIR="ci-artifacts"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a)
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    *)
      echo "[WARN] Unknown argument: $1 (ignored)"
      shift
      ;;
  esac
done

# ---------------------------------------------------------------------
# INITIAL SETUP
# ---------------------------------------------------------------------
REPO_DIR="${GITHUB_WORKSPACE:-$(pwd)}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
# 🧠 use your required model exactly as requested before
MODEL="minimax/minimax-m2:free"

mkdir -p "$ARTIFACT_DIR"
LOG_FILE="$ARTIFACT_DIR/ai_refactor.log"
PROMPT_FILE="$ARTIFACT_DIR/ai_prompt.txt"
RESPONSE_FILE="$ARTIFACT_DIR/ai_response.txt"

cd "$REPO_DIR"
echo "[INFO] Starting AI refactor in: $REPO_DIR" | tee "$LOG_FILE"

# ---------------------------------------------------------------------
# TOOLCHAIN VALIDATION
# ---------------------------------------------------------------------
echo "[INFO] Checking Go toolchain..." | tee -a "$LOG_FILE"
if ! command -v go >/dev/null 2>&1; then
  echo "[ERROR] Go not found. Ensure Go is installed." | tee -a "$LOG_FILE"
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
# STEP 1: LINT + IMPORT FIXES
# ---------------------------------------------------------------------
echo "[INFO] Running goimports..." | tee -a "$LOG_FILE"
goimports -w .

echo "[INFO] Running golangci-lint (auto-fix mode)..." | tee -a "$LOG_FILE"
golangci-lint run --fix --timeout=5m || true

# ---------------------------------------------------------------------
# STEP 2: BUILD & TEST CAPTURE
# ---------------------------------------------------------------------
BUILD_LOG="$ARTIFACT_DIR/build.log"
TEST_LOG="$ARTIFACT_DIR/test.log"
LINT_LOG="$ARTIFACT_DIR/lint.log"

echo "[INFO] Capturing build/test/lint outputs..." | tee -a "$LOG_FILE"

{
  go build ./... 2>&1 || true
  go test ./... 2>&1 || true
} | tee "$BUILD_LOG"

golangci-lint run 2>&1 | tee "$LINT_LOG" || true
go test ./... -v 2>&1 | tee "$TEST_LOG" || true

ERRORS="$(grep -E 'error|FAIL' "$BUILD_LOG" "$TEST_LOG" "$LINT_LOG" || true)"

if [[ -z "$ERRORS" ]]; then
  echo "[INFO] ✅ No errors found — skipping AI refactor." | tee -a "$LOG_FILE"
  exit 0
fi

# ---------------------------------------------------------------------
# STEP 3: GENERATE AI PROMPT
# ---------------------------------------------------------------------
echo "[INFO] Preparing AI refactor prompt..." | tee -a "$LOG_FILE"

cat >"$PROMPT_FILE" <<EOF
You are an expert Go engineer.
Fix the following lint, build, and test errors using idiomatic Go.
Preserve functionality and improve clarity.
Ensure all tests pass after your modifications.
Return only pure Go source code with no commentary or markdown.

Errors to fix:
$ERRORS
EOF

# ---------------------------------------------------------------------
# STEP 4: AI REQUEST VIA OPENROUTER
# ---------------------------------------------------------------------
if [[ -z "$OPENROUTER_API_KEY" ]]; then
  echo "[ERROR] Missing OPENROUTER_API_KEY environment variable." | tee -a "$LOG_FILE"
  exit 1
fi

echo "[INFO] Sending request to OpenRouter ($MODEL)..." | tee -a "$LOG_FILE"

AI_CONTENT="$(curl -sS -X POST "https://openrouter.ai/api/v1/chat/completions" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"model\": \"${MODEL}\",
    \"messages\": [
      {\"role\": \"system\", \"content\": \"You are a senior Go refactoring assistant.\"},
      {\"role\": \"user\", \"content\": $(jq -Rs . < \"$PROMPT_FILE\")}
    ],
    \"temperature\": 0.3
  }" | jq -r '.choices[0].message.content // empty')"

if [[ -z "${AI_CONTENT}" ]]; then
  echo "[ERROR] AI returned empty response." | tee -a "$LOG_FILE"
  exit 1
fi

echo "$AI_CONTENT" > "$RESPONSE_FILE"
echo "[INFO] AI response saved to: $RESPONSE_FILE" | tee -a "$LOG_FILE"

# ---------------------------------------------------------------------
# STEP 5: APPLY AI CHANGES SAFELY
# ---------------------------------------------------------------------
if grep -q "package " "$RESPONSE_FILE"; then
  echo "[INFO] Applying AI-generated code..." | tee -a "$LOG_FILE"
  cp chachacrypt.go "$ARTIFACT_DIR/chachacrypt.go.bak" || true
  echo "$AI_CONTENT" > chachacrypt.go
else
  echo "[WARN] AI output not recognized as Go code. Skipping overwrite." | tee -a "$LOG_FILE"
fi

# ---------------------------------------------------------------------
# STEP 6: VALIDATE POST-AI CHANGES
# ---------------------------------------------------------------------
echo "[INFO] Validating AI-applied changes..." | tee -a "$LOG_FILE"
if go build ./...; then
  echo "[INFO] ✅ Build successful after AI refactor." | tee -a "$LOG_FILE"
else
  echo "[WARN] ⚠ Build failed after AI refactor. Check logs." | tee -a "$LOG_FILE"
fi

go test ./... -v | tee -a "$LOG_FILE" || true

echo "[INFO] ✅ AI refactor completed." | tee -a "$LOG_FILE"
exit 0
