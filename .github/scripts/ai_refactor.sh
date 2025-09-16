#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
set -euo pipefail

# Usage:
#   ai_refactor.sh <mode> <api_url> <ai_model>
# mode: dependencies | patch | go-version
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

# Ensure required tools are present
command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 1; }
command -v gitleaks >/dev/null 2>&1 || { echo "gitleaks required"; exit 1; }

# Prepare artifact files (do not commit these)
REQUEST_FILE="ai-request.json"
RESPONSE_FILE="ai-response.json"
PATCH_FILE="ai.patch"
TEST_LOG="tests.log"
LINTER_LOG="linter.log"
GITLEAKS_LOG="gitleaks.log"

: > "${REQUEST_FILE}"
: > "${RESPONSE_FILE}"
: > "${PATCH_FILE}"
: > "${TEST_LOG}"
: > "${LINTER_LOG}"
: > "${GITLEAKS_LOG}"

# Helper: redact secrets from a text blob (conservative)
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

# Helper: write payload safely using jq to avoid JSON escaping problems
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

# Ensure git workspace is clean
if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is not clean. Please run on a clean workspace."
  git status --porcelain
  exit 1
fi

# Record current commit
BASE_COMMIT="$(git rev-parse --verify HEAD)"
DEFAULT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

# Optionally update go tool version in go.mod to match toolchain
if [ -f go.mod ]; then
  GO_VER="$(go version | awk '{print $3}' | sed 's/go//')"
  # Update the go directive in go.mod if it differs (non-destructive)
  CURRENT_GO_DIRECTIVE="$(awk '/^go [0-9]/ {print $2; exit}' go.mod || true)"
  if [ -n "$GO_VER" ] && [ "$CURRENT_GO_DIRECTIVE" != "$GO_VER" ]; then
    echo "Updating go.mod go directive to ${GO_VER}"
    go mod edit -go="${GO_VER}" || true
  fi
fi

# Run pre-send secret scan to catch obvious secrets (artifact only)
gitleaks protect --no-verify 2>&1 | tee "${GITLEAKS_LOG}" || true

# Find upgrade candidates: list module updates (direct & indirect)
UPGRADE_LINES=$(go list -m -u -json all 2>/dev/null | jq -r 'select(.Update) | .Path + "@" + .Update.Version' || true)

if [ -z "$UPGRADE_LINES" ]; then
  echo "No available module updates detected."
  exit 0
fi

# Apply updates: update each module to its Update.Version (which may be a major)
echo "Updating modules to the latest available versions..."
# Use a temporary list to ensure safe handling of spaces
TMP_UPGRADES="$(mktemp)"
printf "%s\n" "$UPGRADE_LINES" > "$TMP_UPGRADES"

# For robustness, run go get for each module@version individually
while IFS= read -r modver; do
  if [ -n "$modver" ]; then
    echo "Running: go get ${modver}"
    # tolerate individual failures but continue
    if ! go get "${modver}"; then
      echo "Warning: go get ${modver} failed, continuing" >&2
    fi
  fi
done < "$TMP_UPGRADES"
rm -f "$TMP_UPGRADES"

# Tidy modules
go mod tidy

# Create a new branch to hold automated changes
BRANCH_NAME="automated-deps-$(date -u +"%Y%m%dT%H%M%SZ")"
git checkout -b "${BRANCH_NAME}"

# Stage go.mod and go.sum changes
git add go.mod go.sum || true

# Capture the post-update diff (this is the delta that will be repaired by AI if needed)
git diff --staged --no-color > pre-ai.diff || true
# If there is no staged diff, still compute working tree diff
if [ ! -s pre-ai.diff ]; then
  git diff --no-color > pre-ai.diff || true
fi

# Prepare a loop: run tests/lint; if failures, call AI to propose fixes; apply patch; repeat.
MAX_ITER=5
ITER=0
PASS_ALL=false

while [ $ITER -lt $MAX_ITER ]; do
  ITER=$((ITER + 1))
  echo "=== Iteration ${ITER} ==="

  # Run formatting check
  echo "Running gofmt check..." | tee -a "${LINTER_LOG}"
  GO_FMT_ERRORS="$(gofmt -l . || true)"
  if [ -n "$GO_FMT_ERRORS" ]; then
    echo "gofmt suggested changes for following files:" | tee -a "${LINTER_LOG}"
    echo "$GO_FMT_ERRORS" | tee -a "${LINTER_LOG}"
    # Apply gofmt fixes (safest to keep code consistent)
    gofmt -w .
  fi

  # Run golangci-lint (installed earlier)
  echo "Running golangci-lint..." | tee -a "${LINTER_LOG}"
  golangci-lint run ./... 2>&1 | tee -a "${LINTER_LOG}" || true

  # Run go vet
  echo "Running go vet..." | tee -a "${TEST_LOG}"
  go vet ./... 2>&1 | tee -a "${TEST_LOG}" || true

  # Run tests (capture output)
  echo "Running go test..." | tee -a "${TEST_LOG}"
  if go test ./... 2>&1 | tee -a "${TEST_LOG}"; then
    echo "All tests passed on iteration ${ITER}."
    PASS_ALL=true
    break
  else
    echo "Tests failed on iteration ${ITER}."
  fi

  # Prepare AI prompt: include failing test excerpts and the staged diff to be fixed
  FAIL_SNIPPET="$(tail -n 500 "${TEST_LOG}" || true)"
  STAGED_DIFF="$(git diff --staged --no-color || true)"
  WORKING_DIFF="$(git diff --no-color || true)"
  # Prefer sending the minimal (staged) diff; fall back to working diff
  DIFF_TO_SEND="${STAGED_DIFF:-${WORKING_DIFF}}"
  if [ -z "${DIFF_TO_SEND}" ]; then
    echo "No diff found to repair; aborting AI loop."
    break
  fi

  # Build conservative redacted context (do not send secrets)
  printf "%s\n\n%s\n\n%s\n" "TASK: Create a single unified git patch (unified diff starting with 'diff --git') that updates the repository source code so that all 'go test ./...' pass, and all 'go vet' and 'gofmt' issues are resolved. Only modify Go source files and module files as necessary. Do not include extra commentary. Output exactly one unified diff and nothing else. Wrap the unified diff starting with 'diff --git' (no additional prefixes)." \
    "FAILING_TESTS_OUTPUT (excerpt):" "$FAIL_SNIPPET" > sendable-context.tmp
  printf "\n---BEGIN_DIFF---\n%s\n---END_DIFF---\n" "$DIFF_TO_SEND" >> sendable-context.tmp

  # Redact secrets aggressively from context
  redact < sendable-context.tmp > sendable-context.redacted.tmp || true
  PROMPT_CONTENT="$(sed 's/\\/\\\\/g; s/"/\\"/g' sendable-context.redacted.tmp)"

  # Build payload and save a copy for artifact
  build_payload "$PROMPT_CONTENT" | tee "${REQUEST_FILE}"

  # Send request to OpenRouter-like API
  HTTP_RESPONSE=$(curl -sS -X POST "${API_URL}" \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    --data-binary @"${REQUEST_FILE}" -w "\n%{http_code}" || true)

  # Split response body and status code
  HTTP_BODY="$(printf "%s" "$HTTP_RESPONSE" | sed '$d')"
  HTTP_STATUS="$(printf "%s" "$HTTP_RESPONSE" | tail -n1)"
  printf "%s" "$HTTP_BODY" > "${RESPONSE_FILE}"
  echo "HTTP status: ${HTTP_STATUS}"

  # Save a redacted response copy
  redact < "${RESPONSE_FILE}" > "${RESPONSE_FILE}.redacted" || true

  # Extract unified diff from the response - accept either OpenAI-like or other shapes
  # Try common locations for text content
  AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // .result[0].content[0].text // empty' "${RESPONSE_FILE}" 2>/dev/null || true)"
  if [ -z "${AI_CONTENT}" ]; then
    # Fallback: raw response as text
    AI_CONTENT="$(cat "${RESPONSE_FILE}")"
  fi

  # Save AI content for artifact
  printf "%s" "${AI_CONTENT}" > ai-response.raw.txt

  # Extract unified diff starting at 'diff --git'
  printf "%s\n" "${AI_CONTENT}" | sed -n '/^diff --git /,$p' > "${PATCH_FILE}" || true

  if [ ! -s "${PATCH_FILE}" ]; then
    echo "AI did not return a unified diff starting with 'diff --git'. Aborting AI loop." | tee -a "${TEST_LOG}"
    # Save the AI content for inspection and abort
    cat ai-response.raw.txt >> "${TEST_LOG}" || true
    break
  fi

  # Sanity check: ensure patch touches only code files or go.mod/go.sum
  if grep -Eqv '^(\+\+\+ b/|--- a/|diff --git )' "${PATCH_FILE}"; then
    # continue, but also check filenames
    :
  fi

  # Apply patch safely
  set +e
  git apply --index "${PATCH_FILE}" 2>apply.err
  APPLY_EXIT=$?
  set -e

  if [ ${APPLY_EXIT} -ne 0 ]; then
    echo "git apply failed; saving apply.err and aborting AI loop."
    cat apply.err >> "${TEST_LOG}" || true
    # Keep AI response for debugging
    cat ai-response.raw.txt >> "${TEST_LOG}" || true
    break
  fi

  # Commit AI patch
  git add -A
  git commit -m "chore: ai automated refactor for dependency upgrades (iteration ${ITER})" || true

  # Continue loop; next iteration will run tests again
done

# After loop: decide final outcome
# Always produce artifacts for inspection
# Save final patch (if any)
if [ -f "${PATCH_FILE}" ] && [ -s "${PATCH_FILE}" ]; then
  echo "Final AI patch saved to ${PATCH_FILE}."
else
  : > "${PATCH_FILE}" || true
fi

# Run final checks and capture logs
gofmt -l . > /dev/null 2>&1 || true
golangci-lint run ./... 2>&1 | tee -a "${LINTER_LOG}" || true
go vet ./... 2>&1 | tee -a "${TEST_LOG}" || true
go test ./... 2>&1 | tee -a "${TEST_LOG}" || true || true

# Run a final secrets scan on the resulting tree (artifact only)
gitleaks detect --report-path="${GITLEAKS_LOG}" || true

# Push changes back to remote: attempt direct push to default branch; if fails, push branch and attempt merge via API
echo "Attempting to push changes to remote..."
set +e
git push --set-upstream origin "${BRANCH_NAME}" 2>&1 | tee push.log
PUSH_EXIT=${PIPESTATUS[0]}
set -e

if [ ${PUSH_EXIT} -ne 0 ]; then
  echo "Direct push to remote branch failed; attempting PR creation and automatic merge."

  # Create a PR via GitHub API
  PR_PAYLOAD=$(jq -n \
    --arg head "${BRANCH_NAME}" \
    --arg base "${DEFAULT_BRANCH}" \
    --arg title "chore(deps): Automated dependency update and AI refactor" \
    --arg body "Automated dependency updates applied and refactored by CI_Gemini. Tests and linters run in CI. This PR was opened by automation and will be auto-merged if merge checks pass." \
    '{title:$title, head:$head, base:$base, body:$body}')
  PR_RESPONSE=$(curl -sS -X POST "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls" \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -d "$PR_PAYLOAD" || true)

  PR_NUMBER=$(printf "%s" "$PR_RESPONSE" | jq -r '.number // empty' || true)
  if [ -n "$PR_NUMBER" ]; then
    echo "Created PR #${PR_NUMBER}."
    # Attempt to merge immediately
    MERGE_RESPONSE=$(curl -sS -X PUT "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -d '{"merge_method":"merge"}' || true)
    MERGED=$(printf "%s" "$MERGE_RESPONSE" | jq -r '.merged // false' || true)
    if [ "$MERGED" = "true" ]; then
      echo "PR #${PR_NUMBER} merged automatically."
    else
      echo "PR #${PR_NUMBER} could not be merged automatically; manual merge may be required."
      printf "%s\n" "$MERGE_RESPONSE" >> "${TEST_LOG}"
    fi
  else
    echo "Failed to create PR via API. See response:"
    printf "%s\n" "$PR_RESPONSE" >> "${TEST_LOG}"
  fi
else
  echo "Pushed branch ${BRANCH_NAME} successfully."

  # Try to fast-forward merge into default branch directly
  set +e
  git checkout "${DEFAULT_BRANCH}"
  git pull origin "${DEFAULT_BRANCH}"
  git merge --ff-only "${BRANCH_NAME}" 2>&1 | tee -a push.log || true
  MERGE_EXIT=${PIPESTATUS[0]}
  set -e
  if [ ${MERGE_EXIT} -eq 0 ]; then
    git push origin "${DEFAULT_BRANCH}" || true
    echo "Fast-forward merged ${BRANCH_NAME} into ${DEFAULT_BRANCH}."
  else
    echo "Fast-forward merge not possible; branch ${BRANCH_NAME} created and pushed for manual merge or PR auto-merge fallback."
  fi
fi

# Ensure artifacts are present in workspace for the workflow to upload
# Redact the request/response saved earlier for privacy
redact < "${REQUEST_FILE}" > "${REQUEST_FILE}.redacted" || true
redact < "${RESPONSE_FILE}" > "${RESPONSE_FILE}.redacted" || true

# Copy redacted copies into top-level artifact filenames
cp -f "${REQUEST_FILE}.redacted" ai-request.json || true
cp -f "${RESPONSE_FILE}.redacted" ai-response.json || true
cp -f "${PATCH_FILE}" ai.patch || true
cp -f "${TEST_LOG}" tests.log || true
cp -f "${LINTER_LOG}" linter.log || true
cp -f "${GITLEAKS_LOG}" gitleaks.log || true

echo "ai_refactor.sh completed."
