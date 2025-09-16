#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
set -euo pipefail

# Usage:
#   ai_refactor.sh <mode> <api_url> <ai_model>
MODE="${1:-}"
API_URL="${2:-}"
AI_MODEL="${3:-}"

if [ -z "$MODE" ] || [ -z "$API_URL" ] || [ -z "$AI_MODEL" ]; then
  echo "Usage: $0 <mode> <api_url> <ai_model>"
  exit 1
fi

if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY not set"
  exit 1
fi

# Required commands (these are provided by the workflow steps / runner)
for cmd in git go jq curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required command not found in PATH: $cmd" >&2
    exit 1
  fi
done

REQUEST_FILE="ai-request.json"
RESPONSE_FILE="ai-response.json"
PATCH_FILE="ai.patch"
TEST_LOG="tests.log"
LINTER_LOG="linter.log"
PRE_DIFF="pre-ai.diff"
PUSH_LOG="push.log"

: > "${REQUEST_FILE}"
: > "${RESPONSE_FILE}"
: > "${PATCH_FILE}"
: > "${TEST_LOG}"
: > "${LINTER_LOG}"
: > "${PRE_DIFF}"
: > "${PUSH_LOG}"

# Conservative redact function for artifacts
redact() {
  sed -E \
    -e 's/AKIA[0-9A-Z]{16}/REDACTED_AWS_ACCESS_KEY/g' \
    -e 's/ASIA[0-9A-Z]{16}/REDACTED_AWS_SESSION_KEY/g' \
    -e 's/[A-Za-z0-9_+=\/-]{40,}/REDACTED_LONG_TOKEN/g' \
    -e 's/-----BEGIN( RSA|) PRIVATE KEY-----/REDACTED_PRIVATE_KEY_BEGIN/g' \
    -e 's/-----END( RSA|) PRIVATE KEY-----/REDACTED_PRIVATE_KEY_END/g' \
    -e 's/github_pat_[A-Za-z0-9_]{36,}/REDACTED_GITHUB_PAT/g' \
    -e 's/ghp_[A-Za-z0-9_]{36,}/REDACTED_GITHUB_PAT/g' \
    -e 's/-----BEGIN CERTIFICATE-----/REDACTED_CERT_BEGIN/g' \
    -e 's/-----END CERTIFICATE-----/REDACTED_CERT_END/g'
}

# Build JSON payload safely
build_payload() {
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

# Ensure clean workspace
if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is not clean. Please run on a clean workspace."
  git status --porcelain
  exit 1
fi

BASE_COMMIT="$(git rev-parse --verify HEAD)"
DEFAULT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

# If go.mod exists, ensure go directive matches installed toolchain (non-destructive)
if [ -f go.mod ]; then
  GO_VER_RAW="$(go version | awk '{print $3}')"
  GO_VER="${GO_VER_RAW#go}"
  CURRENT_GO_DIRECTIVE="$(awk '/^go [0-9]/ {print $2; exit}' go.mod || true)"
  if [ -n "$GO_VER" ] && [ "$CURRENT_GO_DIRECTIVE" != "$GO_VER" ]; then
    echo "Updating go.mod go directive to ${GO_VER}"
    go mod edit -go="${GO_VER}" || true
  fi
fi

# List available module updates
echo "Detecting available module updates..."
UPGRADE_LINES=$(go list -m -u -json all 2>/dev/null | jq -r 'select(.Update) | .Path + "@" + .Update.Version' || true)

if [ -z "$UPGRADE_LINES" ]; then
  echo "No available module updates detected."
  exit 0
fi

# Save list for debug
printf "%s\n" "$UPGRADE_LINES" > candidate-upgrades.txt

# Apply updates: run go get for each update candidate (may include major bumps)
echo "Updating modules to the available versions..." | tee -a "${PRE_DIFF}"
TMP_UPGRADES="$(mktemp)"
printf "%s\n" "$UPGRADE_LINES" > "$TMP_UPGRADES"

while IFS= read -r modver; do
  if [ -n "$modver" ]; then
    echo "Running: go get ${modver}" | tee -a "${PRE_DIFF}"
    if ! go get "${modver}" 2>&1 | tee -a "${PRE_DIFF}"; then
      echo "Warning: go get ${modver} failed; continuing" | tee -a "${PRE_DIFF}"
    fi
  fi
done < "$TMP_UPGRADES"
rm -f "$TMP_UPGRADES"

# Tidy modules
go mod tidy 2>&1 | tee -a "${PRE_DIFF}"

# Create a branch to hold automated changes
BRANCH_NAME="automated-deps-$(date -u +"%Y%m%dT%H%M%SZ")"
git checkout -b "${BRANCH_NAME}"

# Stage mod changes and record pre-AI diff
git add go.mod go.sum || true
git diff --staged --no-color > "${PRE_DIFF}" || true
if [ ! -s "${PRE_DIFF}" ]; then
  git diff --no-color > "${PRE_DIFF}" || true
fi

# Iterative repair loop: run format/vet/tests, ask AI for a patch when failures occur, apply patch, repeat.
MAX_ITER=5
ITER=0
PASS_ALL=false

while [ $ITER -lt $MAX_ITER ]; do
  ITER=$((ITER + 1))
  echo "=== Iteration ${ITER} ===" | tee -a "${TEST_LOG}"

  # Format code (in-place)
  echo "Running gofmt..." | tee -a "${LINTER_LOG}"
  GO_FMT_ERRORS="$(gofmt -l . || true)"
  if [ -n "$GO_FMT_ERRORS" ]; then
    echo "gofmt will reformat files:" | tee -a "${LINTER_LOG}"
    echo "$GO_FMT_ERRORS" | tee -a "${LINTER_LOG}"
    gofmt -w .
    git add -A
  fi

  # Run go vet
  echo "Running go vet..." | tee -a "${TEST_LOG}"
  if go vet ./... 2>&1 | tee -a "${TEST_LOG}"; then
    echo "go vet completed." | tee -a "${TEST_LOG}"
  else
    echo "go vet reported issues; see ${TEST_LOG}" | tee -a "${TEST_LOG}"
  fi

  # Run tests
  echo "Running go test..." | tee -a "${TEST_LOG}"
  if go test ./... 2>&1 | tee -a "${TEST_LOG}"; then
    echo "All tests passed on iteration ${ITER}." | tee -a "${TEST_LOG}"
    PASS_ALL=true
    break
  else
    echo "Tests failed on iteration ${ITER}." | tee -a "${TEST_LOG}"
  fi

  # Prepare diff to send to AI (staged preferred, else working)
  STAGED_DIFF="$(git diff --staged --no-color || true)"
  WORKING_DIFF="$(git diff --no-color || true)"
  DIFF_TO_SEND="${STAGED_DIFF:-${WORKING_DIFF}}"
  if [ -z "${DIFF_TO_SEND}" ]; then
    echo "No diff found to repair; aborting AI loop." | tee -a "${TEST_LOG}"
    break
  fi

  # Create prompt (redacted) with failing test excerpt and diff
  FAIL_SNIPPET="$(tail -n 800 "${TEST_LOG}" || true)"
  {
    printf "%s\n\n%s\n\n%s\n" \
      "TASK: Create a single unified git patch (unified diff starting with 'diff --git') that updates the repository source code so that all 'go test ./...' pass, and all 'go vet' and 'gofmt' issues are resolved. Only modify Go source files and module files as necessary. Do not include extra commentary. Output exactly one unified diff and nothing else. Wrap the unified diff starting with 'diff --git' (no additional prefixes)." \
      "FAILING_TESTS_OUTPUT (excerpt):" \
      "$FAIL_SNIPPET"
    printf "\n---BEGIN_DIFF---\n%s\n---END_DIFF---\n" "$DIFF_TO_SEND"
  } > sendable-context.tmp

  redact < sendable-context.tmp > sendable-context.redacted.tmp || true
  PROMPT_CONTENT="$(sed 's/\\/\\\\/g; s/"/\\"/g' sendable-context.redacted.tmp)"

  build_payload "$PROMPT_CONTENT" | tee "${REQUEST_FILE}"

  # Call the AI model via OpenRouter-like endpoint
  HTTP_RESPONSE=$(curl -sS -X POST "${API_URL}" \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    --data-binary @"${REQUEST_FILE}" -w "\n%{http_code}" || true)

  HTTP_BODY="$(printf "%s" "$HTTP_RESPONSE" | sed '$d')"
  HTTP_STATUS="$(printf "%s" "$HTTP_RESPONSE" | tail -n1)"
  printf "%s" "$HTTP_BODY" > "${RESPONSE_FILE}"
  echo "HTTP status: ${HTTP_STATUS}" | tee -a "${TEST_LOG}"

  redact < "${RESPONSE_FILE}" > "${RESPONSE_FILE}.redacted" || true

  # Extract AI content from common response shapes
  AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // .result[0].content[0].text // empty' "${RESPONSE_FILE}" 2>/dev/null || true)"
  if [ -z "${AI_CONTENT}" ]; then
    AI_CONTENT="$(cat "${RESPONSE_FILE}")"
  fi

  printf "%s" "${AI_CONTENT}" > ai-response.raw.txt

  # Extract unified diff starting with 'diff --git'
  printf "%s\n" "${AI_CONTENT}" | sed -n '/^diff --git /,$p' > "${PATCH_FILE}" || true

  if [ ! -s "${PATCH_FILE}" ]; then
    echo "AI did not return a unified diff starting with 'diff --git'. Aborting AI loop." | tee -a "${TEST_LOG}"
    cat ai-response.raw.txt >> "${TEST_LOG}" || true
    break
  fi

  # Apply patch
  set +e
  git apply --index "${PATCH_FILE}" 2>apply.err
  APPLY_EXIT=$?
  set -e

  if [ ${APPLY_EXIT} -ne 0 ]; then
    echo "git apply failed; saving apply.err and aborting AI loop." | tee -a "${TEST_LOG}"
    cat apply.err >> "${TEST_LOG}" || true
    cat ai-response.raw.txt >> "${TEST_LOG}" || true
    break
  fi

  # Commit AI patch
  git add -A
  git commit -m "chore: ai automated refactor for dependency upgrades (iteration ${ITER})" || true

  # continue to next iteration to re-run tests/lint
done

# Final checks (capture logs)
gofmt -l . > /dev/null 2>&1 || true
go vet ./... 2>&1 | tee -a "${TEST_LOG}" || true
go test ./... 2>&1 | tee -a "${TEST_LOG}" || true || true

# Push changes / create PR
echo "Attempting to push changes to remote..." | tee -a "${PUSH_LOG}"
set +e
git push --set-upstream origin "${BRANCH_NAME}" 2>&1 | tee -a "${PUSH_LOG}"
PUSH_EXIT=${PIPESTATUS[0]}
set -e

if [ ${PUSH_EXIT} -ne 0 ]; then
  echo "Push failed; attempting to create a pull request via GitHub API." | tee -a "${PUSH_LOG}"
  PR_PAYLOAD=$(jq -n \
    --arg head "${BRANCH_NAME}" \
    --arg base "${DEFAULT_BRANCH}" \
    --arg title "chore(deps): Automated dependency update and AI refactor" \
    --arg body "Automated dependency updates applied and refactored by CI_Gemini. Tests and linters were run in CI. This PR was opened by automation." \
    '{title:$title, head:$head, base:$base, body:$body}')
  PR_RESPONSE=$(curl -sS -X POST "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls" \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -d "$PR_PAYLOAD" || true)
  PR_NUMBER=$(printf "%s" "$PR_RESPONSE" | jq -r '.number // empty' || true)
  if [ -n "$PR_NUMBER" ]; then
    echo "Created PR #${PR_NUMBER}." | tee -a "${PUSH_LOG}"
  else
    echo "Failed to create PR via API; see push.log for details." | tee -a "${PUSH_LOG}"
    printf "%s\n" "$PR_RESPONSE" >> "${PUSH_LOG}"
  fi
else
  echo "Pushed branch ${BRANCH_NAME} successfully." | tee -a "${PUSH_LOG}"
fi

# Prepare artifacts (redacted)
redact < "${REQUEST_FILE}" > "${REQUEST_FILE}.redacted" || true
redact < "${RESPONSE_FILE}" > "${RESPONSE_FILE}.redacted" || true

cp -f "${REQUEST_FILE}.redacted" ai-request.json || true
cp -f "${RESPONSE_FILE}.redacted" ai-response.json || true
cp -f "${PATCH_FILE}" ai.patch || true
cp -f "${TEST_LOG}" tests.log || true
cp -f "${LINTER_LOG}" linter.log || true
cp -f "${PRE_DIFF}" pre-ai.diff || true
cp -f "${PUSH_LOG}" push.log || true

echo "ai_refactor.sh completed."
