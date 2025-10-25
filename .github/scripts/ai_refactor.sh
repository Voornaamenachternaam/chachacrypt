#!/usr/bin/env bash
# =====================================================================
# ai_refactor.sh — Automatic AI-driven Go refactor script
# Integrates golangci-lint, goimports, and OpenRouter AI model
# =====================================================================

set -euo pipefail

# ---------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------
MODEL="minimax/minimax-m2:free"           # ✅ Your required AI model
GOLANGCI_LINT_VERSION="v2.5.0"

REPO_DIR="${GITHUB_WORKSPACE:-$(pwd)}"
ARTIFACT_DIR="ci-artifacts"

# Argument parsing
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

mkdir -p "$ARTIFACT_DIR"
LOG_FILE="$ARTIFACT_DIR/ai_refactor.log"
PROMPT_FILE="$ARTIFACT_DIR/ai_prompt.txt"
RESPONSE_FILE="$ARTIFACT_DIR/ai_response.txt"

echo "[INFO] Starting AI refactor in: $REPO_DIR" | tee "$LOG_FILE"
cd "$REPO_DIR"

# ---------------------------------------------------------------------
# TOOLCHAIN CHECKS
# ---------------------------------------------------------------------
echo "[INFO] Checking Go toolchain..." | tee -a "$LOG_FILE"

if ! command -v go >/dev/null 2>&1; then
  echo "[ERROR] Go not found in PATH." | tee -a "$LOG_FILE"
  exit 1
fi

if ! command -v goimports >/dev/null 2>&1; then
  echo "[INFO] Installing goimports..." | tee -a "$LOG_FILE"
  go install golang.org/x/tools/cmd/goimports@latest
fi

if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "[INFO] Installing golangci-lint $GOLANGCI_LINT_VERSION..." | tee -a "$LOG_FILE"
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$(go env GOPATH)/bin" "$GOLANGCI_LINT_VERSION"
fi

export PATH="$(go env GOPATH)/bin:$PATH"

# ---------------------------------------------------------------------
# STEP 1: LINT + IMPORTS
# ---------------------------------------------------------------------
echo "[INFO] Running goimports..." | tee -a "$LOG_FILE"
goimports -w .

echo "[INFO] Running golangci-lint auto-fix..." | tee -a "$LOG_FILE"
golangci-lint run --fix --timeout=5m || true

# ---------------------------------------------------------------------
# STEP 2: BUILD/TEST CAPTURE
# ---------------------------------------------------------------------
BUILD_LOG="$ARTIFACT_DIR/build.log"
TEST_LOG="$ARTIFACT_DIR/test.log"
LINT_LOG="$ARTIFACT_DIR/lint.log"

{
  go build ./... 2>&1 || true
  go test ./... 2>&1 || true
} | tee "$BUILD_LOG"

golangci-lint run 2>&1 | tee "$LINT_LOG" || true
go test ./... -v 2>&1 | tee "$TEST_LOG" || true

ERRORS="$(grep -E 'error|FAIL|undefined' "$BUILD_LOG" "$TEST_LOG" "$LINT_LOG" || true)"

if [[ -z "$ERRORS" ]]; then
  echo "[INFO] ✅ No errors found — skipping AI refactor." | tee -a "$LOG_FILE"
  exit 0
fi

# ---------------------------------------------------------------------
# STEP 3: PREPARE PROMPT
# ---------------------------------------------------------------------
echo "[INFO] Preparing AI refactor prompt..." | tee -a "$LOG_FILE"

cat >"$PROMPT_FILE" <<EOF
You are an expert Go engineer.
Fix the following Go source errors automatically:
- Ensure code compiles and passes all tests.
- Correct all golangci-lint issues.
- Do not alter core logic unnecessarily.
- Return only valid Go code with no markdown.

Detected issues:
$ERRORS
EOF

# ---------------------------------------------------------------------
# STEP 4: CALL OPENROUTER AI
# ---------------------------------------------------------------------
if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "[ERROR] OPENROUTER_API_KEY not set." | tee -a "$LOG_FILE"
  exit 1
fi

echo "[INFO] Sending request to OpenRouter ($MODEL)..." | tee -a "$LOG_FILE"

AI_CONTENT="$(curl -sS -X POST "https://openrouter.ai/api/v1/chat/completions" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"model\": \"${MODEL}\",
    \"messages\": [
      {\"role\": \"system\", \"content\": \"You are a senior Go code refactoring assistant.\"},
      {\"role\": \"user\", \"content\": $(jq -Rs . < \"$PROMPT_FILE\")}
    ],
    \"temperature\": 0.2
  }" | jq -r '.choices[0].message.content // empty')"

if [[ -z "$AI_CONTENT" ]]; then
  echo "[ERROR] AI returned empty response." | tee -a "$LOG_FILE"
  exit 1
fi

echo "$AI_CONTENT" > "$RESPONSE_FILE"
echo "[INFO] AI response saved: $RESPONSE_FILE" | tee -a "$LOG_FILE"

# ---------------------------------------------------------------------
# STEP 5: APPLY AI OUTPUT
# ---------------------------------------------------------------------
if grep -q "package " "$RESPONSE_FILE"; then
  echo "[INFO] Applying AI-generated code..." | tee -a "$LOG_FILE"
  cp chachacrypt.go "$ARTIFACT_DIR/chachacrypt.go.bak" || true
  echo "$AI_CONTENT" > chachacrypt.go
else
  echo "[WARN] AI output not recognized as Go source. Skipping overwrite." | tee -a "$LOG_FILE"
fi

# ---------------------------------------------------------------------
# STEP 6: REVALIDATE BUILD
# ---------------------------------------------------------------------
if go build ./...; then
  echo "[INFO] ✅ Build successful after AI refactor." | tee -a "$LOG_FILE"
else
  echo "[WARN] Build failed after AI refactor. Review logs." | tee -a "$LOG_FILE"
fi

go test ./... -v | tee -a "$LOG_FILE" || true
echo "[INFO] ✅ AI refactor process complete." | tee -a "$LOG_FILE"
exit 0
