#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
set -euo pipefail

MODE="${1:-}"
API_URL="${2:-}"
AI_MODEL="${3:-}"

if [ -z "$MODE" ] || [ -z "$API_URL" ] || [ -z "$AI_MODEL" ]; then
  echo "Usage: $0 <mode> <api_url> <ai_model>"
  exit 1
fi

# Ensure required secrets and tools are present
if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY not set" >&2
  exit 1
fi
if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "GITHUB_TOKEN not set" >&2
  exit 1
fi
for cmd in git go jq curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required command not found in PATH: $cmd" >&2
    exit 1
  fi
done

# Function to build JSON for AI prompt
build_prompt() {
  local prompt="$1"
  jq -n --arg model "$AI_MODEL" --arg system "You are an expert Go engineer." \
         --arg user "$prompt" \
         '{
           model: $model,
           messages: [
             { role: "system", content: $system },
             { role: "user", content: $user }
           ],
           temperature: 0.0,
           max_tokens: 32768
         }'
}

WORKSPACE_DIR="${GITHUB_WORKSPACE:-$(pwd)}"
TMP_ROOT="$(mktemp -d)"
REQUEST_FILE="$TMP_ROOT/ai-request.json"
RESPONSE_FILE="$TMP_ROOT/ai-response.json"
PATCH_FILE="$TMP_ROOT/ai.patch"
TEST_LOG="$TMP_ROOT/tests.log"
LINTER_LOG="$TMP_ROOT/linter.log"
PRE_DIFF="$TMP_ROOT/pre-ai.diff"
PUSH_LOG="$TMP_ROOT/push.log"
AI_RAW="$TMP_ROOT/ai-response-raw.txt"

: > "${REQUEST_FILE}"
: > "${RESPONSE_FILE}"
: > "${PATCH_FILE}"
: > "${TEST_LOG}"
: > "${LINTER_LOG}"
: > "${PRE_DIFF}"
: > "${PUSH_LOG}"
: > "${AI_RAW}"

# Clone repository using the GH token (GH2_TOKEN) for auth
GIT_CLONE_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
echo "Cloning repository..."
git clone --depth=1 --no-single-branch "${GIT_CLONE_URL}" "$TMP_ROOT/repo"
cd "$TMP_ROOT/repo"
git config user.name "ci-grok4-bot"
git config user.email "ci-grok4-bot@users.noreply.github.com"

# Align go.mod 'go' version with actual Go version on runner
if [ -f go.mod ]; then
  GO_VER_RAW="$(go version | awk '{print $3}')"
  GO_VER="${GO_VER_RAW#go}"
  CURRENT_GO_DIRECTIVE="$(awk '/^go [0-9]/ {print $2; exit}' go.mod || true)"
  if [ -n "$GO_VER" ] && [ "$CURRENT_GO_DIRECTIVE" != "$GO_VER" ]; then
    echo "Updating go.mod to Go version $GO_VER"
    go mod edit -go="${GO_VER}" || true
  fi
fi

# Stage only go.mod/go.sum for dependency updates
git add go.mod go.sum 2>/dev/null || true
go mod tidy >> "${LINTER_LOG}" 2>&1 || true

PRE_DIFF_FILE="$WORKSPACE_DIR/pre-ai.diff"
git checkout -b "automated-deps-$(date -u +"%Y%m%dT%H%M%SZ")"
git add go.mod go.sum 2>/dev/null || true
git diff --staged --no-color > "${PRE_DIFF_FILE}" || true
if [ ! -s "${PRE_DIFF_FILE}" ]; then
  git diff --no-color > "${PRE_DIFF_FILE}" || true
fi

# Iteratively apply AI-generated patches
MAX_ITER=5
ITER=0
while [ $ITER -lt $MAX_ITER ]; do
  ITER=$((ITER + 1))
  echo "=== Iteration ${ITER} ===" | tee -a "${TEST_LOG}"

  # Run gofmt and auto-fix formatting
  GO_FMT_ERR="$(gofmt -l . || true)"
  if [ -n "$GO_FMT_ERR" ]; then
    echo "Running gofmt..." | tee -a "${LINTER_LOG}"
    gofmt -w .
    git add -A
  fi

  # Build and send AI prompt to update dependencies/code
  PROMPT_TEXT=$(cat <<EOF
Automatically update dependencies in go.mod (if needed) and apply code refactors to improve code quality. Return a unified git patch.
EOF
)
  echo "Building AI request..."
  build_prompt "$PROMPT_TEXT" > "${REQUEST_FILE}"
  curl -s -X POST "$API_URL" \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    -d @"${REQUEST_FILE}" \
    -o "${RESPONSE_FILE}" 2>> "${LINTER_LOG}"
  cat "${RESPONSE_FILE}" | jq -r '.choices[0].message.content' > "${AI_RAW}"

  # Convert AI response to patch (assumes raw content is unified diff)
  if ! echo "${AI_RAW}" | git apply --check - 2> /dev/null; then
    echo "AI-generated patch failed to apply cleanly." | tee -a "${TEST_LOG}"
    echo "${AI_RAW}" >> "${TEST_LOG}"
    break
  fi
  echo "${AI_RAW}" > "${PATCH_FILE}"

  git apply --index "${PATCH_FILE}" 2> "${TMP_ROOT}/apply.err"
  APPLY_EXIT=$?
  if [ $APPLY_EXIT -ne 0 ]; then
    echo "git apply failed; saving error and aborting." | tee -a "${TEST_LOG}"
    cat "${TMP_ROOT}/apply.err" >> "${TEST_LOG}" || true
    cat "${AI_RAW}" >> "${TEST_LOG}" || true
    break
  fi

  git add -A
  git commit -m "chore: AI-assisted refactor and dependency update (iteration ${ITER})" || true
done

# Redact sensitive data in outputs, save to workspace
redact() { sed -E -e 's/(Authorization: Bearer )[A-Za-z0-9_-]+/\1REDACTED_TOKEN/g'; }
redact < "${REQUEST_FILE}" > "${WORKSPACE_DIR}/ai-request.json" || true
redact < "${RESPONSE_FILE}" > "${WORKSPACE_DIR}/ai-response.json" || true
cp "${PATCH_FILE}" "${WORKSPACE_DIR}/ai.patch" || true
cp "${TEST_LOG}" "${WORKSPACE_DIR}/tests.log" || true
cp "${LINTER_LOG}" "${WORKSPACE_DIR}/linter.log" || true
cp "${PRE_DIFF_FILE}" "${WORKSPACE_DIR}/pre-ai.diff" || true
cp "${PUSH_LOG}" "${WORKSPACE_DIR}/push.log" || true
cp "${AI_RAW}" "${WORKSPACE_DIR}/ai-response-raw.txt" || true

# Clean up
cd "${WORKSPACE_DIR}"
rm -rf "$TMP_ROOT"

echo "ai_refac tor.sh completed."
