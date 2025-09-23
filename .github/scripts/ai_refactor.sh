#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# AI-assisted dependency updater and refactorer for Go projects.
# Usage: ./ai_refactor.sh <mode> <api_url> <ai_model>
set -euo pipefail

MODE="${1:-}"
API_URL="${2:-}"
AI_MODEL="${3:-}"

if [ -z "$MODE" ] || [ -z "$API_URL" ] || [ -z "$AI_MODEL" ]; then
  echo "Usage: $0 <mode> <api_url> <ai_model>"
  exit 1
fi

# Required environment variables:
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set}"   # GH2_TOKEN is passed into the workflow and mapped to GITHUB_TOKEN

for cmd in git go jq curl sed awk cmp mkdir mktemp date; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required command not found: $cmd" >&2
    exit 1
  fi
done

# Utility: redact tokens for saved artifacts
redact_stream() {
  sed -E \
    -e 's/(Authorization: Bearer )[A-Za-z0-9._-]+/\1REDACTED_TOKEN/g' \
    -e 's/"openai_api_key"\s*:\s*"[^"]+"/"openai_api_key":"REDACTED_TOKEN"/g' \
    -e 's/"api_key"\s*:\s*"[^"]+"/"api_key":"REDACTED_TOKEN"/g' \
    -e 's/[\t ]*([A-Z0-9_]{20,})[A-Za-z0-9_+-\/]{20,}/REDACTED_TOKEN/g' \
    -e '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/c\\[REDACTED PRIVATE KEY\\]'
}

# Prepare temporary workspace
TMP_ROOT="$(mktemp -d)"
REQUEST_FILE="${TMP_ROOT}/ai-request.json"
RESPONSE_TMP="${TMP_ROOT}/ai-response.tmp"
RESPONSE_FILE="${TMP_ROOT}/ai-response.json"
AI_RAW="${TMP_ROOT}/ai-response-raw.txt"
PATCH_FILE="${TMP_ROOT}/ai.patch"
APPLY_ERR="${TMP_ROOT}/apply.err"
TEST_LOG="${TMP_ROOT}/tests.log"
LINTER_LOG="${TMP_ROOT}/linter.log"
PRE_DIFF_TMP="${TMP_ROOT}/pre-ai.diff"
PUSH_LOG="${TMP_ROOT}/push.log"
HTTP_STATUS_FILE="${TMP_ROOT}/http_status.txt"

: > "${REQUEST_FILE}"
: > "${RESPONSE_TMP}"
: > "${RESPONSE_FILE}"
: > "${AI_RAW}"
: > "${PATCH_FILE}"
: > "${APPLY_ERR}"
: > "${TEST_LOG}"
: > "${LINTER_LOG}"
: > "${PRE_DIFF_TMP}"
: > "${PUSH_LOG}"
: > "${HTTP_STATUS_FILE}"

# Work inside a fresh clone to avoid touching workspace files directly
REPO_CLONE_DIR="${TMP_ROOT}/repo"
echo "Cloning repository..."
git clone --depth=1 --no-single-branch "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "${REPO_CLONE_DIR}"

cd "${REPO_CLONE_DIR}"
git config user.name "ci-grok4-bot"
git config user.email "ci-grok4-bot@users.noreply.github.com"

# Record base branch (branch we cloned) and then create a timestamped branch
BASE_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
BRANCH_NAME="automated-deps-$(date -u +"%Y%m%dT%H%M%SZ")"
git checkout -b "${BRANCH_NAME}"
echo "Switched to a new branch '${BRANCH_NAME}' (base: ${BASE_BRANCH})"

# Ensure go.mod 'go' directive matches runtime Go (best-effort)
if [ -f go.mod ]; then
  GO_VER_RAW="$(go version | awk '{print $3}')"
  GO_VER="${GO_VER_RAW#go}"
  CURRENT_GO_DIRECTIVE="$(awk '/^go [0-9]/ {print $2; exit}' go.mod || true)"
  if [ -n "$GO_VER" ] && [ "$CURRENT_GO_DIRECTIVE" != "$GO_VER" ]; then
    echo "Updating go.mod go directive: ${CURRENT_GO_DIRECTIVE} -> ${GO_VER}"
    go mod edit -go="${GO_VER}" || true
    git add go.mod || true
  fi
fi

# Capture a pre-AI diff (for artifacts)
git add -A || true
git diff --staged --no-color > "${PRE_DIFF_TMP}" || true
if [ ! -s "${PRE_DIFF_TMP}" ]; then
  git diff --no-color > "${PRE_DIFF_TMP}" || true
fi

# Helper: build OpenRouter/Chat payload with reasoning enabled
build_payload() {
  local system_msg="$1"
  local user_msg="$2"
  jq -n --arg model "$AI_MODEL" \
        --arg system "$system_msg" \
        --arg user "$user_msg" \
        '{
          model: $model,
          messages: [
            { role: "system", content: $system },
            { role: "user", content: $user }
          ],
          temperature: 0.0,
          max_tokens: 32768,
          include_reasoning: true,
          reasoning: { effort: "high" }
        }'
}

# Helper: extract unified diff from AI response (support fenced code blocks and plain diffs)
extract_unified_diff() {
  local srcfile="$1"
  local out="$2"
  # 1) If any 'diff --git' line exists, take from first occurrence
  if grep -q '^diff --git ' "${srcfile}"; then
    sed -n '/^diff --git /,$p' "${srcfile}" > "${out}"
    [ -s "${out}" ] && return 0
  fi

  # 2) If triple-backtick fenced blocks exist, attempt to extract and then find diff within
  if grep -q '^```' "${srcfile}"; then
    awk 'BEGIN{f=0} /^```/{f=!f; next} f{print}' "${srcfile}" | sed -n '/^diff --git /,$p' > "${out}"
    [ -s "${out}" ] && return 0
  fi

  # 3) As a last resort, try to extract any context-style unified diff by matching @@ and ---/+ lines
  awk 'BEGIN{f=0} /^@@ |^--- |^\+\+\+ |^diff --git /{f=1} f{print}' "${srcfile}" > "${out}"
  [ -s "${out}" ] && return 0

  return 1
}

# Find module updates (if mode is dependencies)
if [ "${MODE}" = "dependencies" ]; then
  echo "Checking for available module updates..." | tee -a "${LINTER_LOG}"
  # produce list of modules with updates
  UPGRADE_LINES="$(go list -m -u -json all 2>/dev/null | jq -r 'select(.Update) | .Path + \"@\" + .Update.Version' || true)"
  if [ -z "${UPGRADE_LINES}" ]; then
    echo "No module updates found; exiting." | tee -a "${LINTER_LOG}"
    # copy artifacts back to original workspace for upload
    # Avoid copying if same file to prevent cp errors
    WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
    mkdir -p "${WORKSPACE}"
    if [ -s "${PRE_DIFF_TMP}" ]; then
      if [ ! -e "${WORKSPACE}/pre-ai.diff" ] || ! cmp -s "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"; then
        cp "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"
      fi
    fi
    # Nothing else to do
    exit 0
  fi

  echo "Modules to attempt upgrade:" | tee -a "${LINTER_LOG}"
  echo "${UPGRADE_LINES}" | tee -a "${LINTER_LOG}"
  # Try to apply each update (best-effort)
  while IFS= read -r m; do
    if [ -n "$m" ]; then
      echo "Attempting go get ${m}" | tee -a "${LINTER_LOG}"
      if GOFLAGS=-mod=mod go get -d "${m}" >> "${LINTER_LOG}" 2>&1; then
        echo "go get ${m} succeeded" >> "${LINTER_LOG}"
      else
        echo "go get ${m} failed (continuing)" >> "${LINTER_LOG}"
      fi
    fi
  done <<< "${UPGRADE_LINES}"
  # Tidy modules (best-effort)
  go mod tidy >> "${LINTER_LOG}" 2>&1 || true
  git add go.mod go.sum 2>/dev/null || true
fi

# Re-create PRE_DIFF_TMP after attempted go get / tidy
git diff --staged --no-color > "${PRE_DIFF_TMP}" || true
if [ ! -s "${PRE_DIFF_TMP}" ]; then
  git diff --no-color > "${PRE_DIFF_TMP}" || true
fi

# Main AI-driven iterative apply loop
MAX_ITER=5
ITER=0
PASS_ALL=false

while [ "$ITER" -lt "$MAX_ITER" ]; do
  ITER=$((ITER + 1))
  echo "=== Iteration ${ITER} ===" | tee -a "${TEST_LOG}"

  # Format fixes
  GOFMT_LIST="$(gofmt -l . || true)"
  if [ -n "${GOFMT_LIST}" ]; then
    echo "Applying gofmt fixes..." | tee -a "${LINTER_LOG}"
    gofmt -w .
    git add -A || true
  fi

  # Run vet (non-fatal)
  echo "Running go vet..." | tee -a "${LINTER_LOG}"
  (go vet ./... >> "${LINTER_LOG}" 2>&1) || true

  # Run tests and capture output
  echo "Running go test (iteration ${ITER})..." | tee -a "${TEST_LOG}"
  if go test ./... 2>&1 | tee -a "${TEST_LOG}"; then
    echo "Tests passed on iteration ${ITER}" | tee -a "${TEST_LOG}"
    PASS_ALL=true
    break
  else
    echo "Tests failing on iteration ${ITER}; preparing AI prompt" | tee -a "${TEST_LOG}"
  fi

  # Prepare diff to send to AI
  DIFF_FILE="${TMP_ROOT}/diff-to-send.patch"
  git add -A || true
  git diff --staged --no-color > "${DIFF_FILE}" || true
  if [ ! -s "${DIFF_FILE}" ]; then
    git diff --no-color > "${DIFF_FILE}" || true
  fi
  if [ ! -s "${DIFF_FILE}" ]; then
    echo "No diff to send to AI; nothing to fix." | tee -a "${TEST_LOG}"
    break
  fi

  # Build the AI prompt: include clear task + failing test snippet + diff
  FAIL_SNIPPET="$(tail -n 800 "${TEST_LOG}" || true)"
  TASK_INSTR="You are an expert Go engineer. Given the failing test output and the following repository diff, produce a single unified git patch (a unified diff starting with 'diff --git') that fixes the failing tests and compiles cleanly. Return only the unified patch (no additional commentary). If you cannot produce a working patch, return an empty response."
  PROMPT_CONTENT="$(printf "%s\n\n=== FAILING TEST OUTPUT ===\n%s\n\n=== REPO DIFF ===\n%s\n" "${TASK_INSTR}" "${FAIL_SNIPPET}" "$(sed -n '1,2000p' "${DIFF_FILE}" || true)")"

  # Build payload with reasoning enabled (OpenRouter)
  build_payload "$TASK_INSTR" "$PROMPT_CONTENT" > "${REQUEST_FILE}"

  # Send request and capture HTTP status + raw response
  HTTP_CODE="$(curl -sS -X POST "${API_URL}" \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    -d @"${REQUEST_FILE}" \
    -w "%{http_code}" -o "${RESPONSE_TMP}" )" || true

  echo "${HTTP_CODE}" > "${HTTP_STATUS_FILE}"
  # Save raw response for debugging
  cat "${RESPONSE_TMP}" > "${AI_RAW}" || true

  # Fail early if non-2xx
  if [ -z "${HTTP_CODE}" ] || [ "${HTTP_CODE}" -lt 200 ] || [ "${HTTP_CODE}" -ge 300 ]; then
    echo "OpenRouter returned HTTP ${HTTP_CODE}; aborting AI loop" | tee -a "${TEST_LOG}" "${LINTER_LOG}"
    # Save redacted response as artifact-ready file
    redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_FILE}" || true
    break
  fi

  # Extract assistant content (support chat/completion variants)
  AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // ""' "${RESPONSE_TMP}" 2>/dev/null || true)"
  # Save raw and redacted response into workspace later; for now keep in AI_RAW
  printf "%s\n" "${AI_CONTENT}" > "${AI_RAW}"

  # Attempt to extract unified diff from AI content
  if ! extract_unified_diff "${AI_RAW}" "${PATCH_FILE}"; then
    echo "AI did not produce a unified diff. Saving AI output and aborting iteration." | tee -a "${TEST_LOG}"
    echo "=== AI RAW OUTPUT ===" >> "${TEST_LOG}"
    sed -n '1,400p' "${AI_RAW}" >> "${TEST_LOG}" || true
    # Save redacted response for artifacts
    redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_FILE}" || true
    break
  fi

  # Validate patch applies cleanly
  if ! git apply --check "${PATCH_FILE}" 2> "${APPLY_ERR}"; then
    echo "git apply --check failed; see apply.err and AI raw output" | tee -a "${TEST_LOG}"
    cat "${APPLY_ERR}" >> "${TEST_LOG}" || true
    echo "=== AI RAW OUTPUT ===" >> "${TEST_LOG}"
    sed -n '1,400p' "${AI_RAW}" >> "${TEST_LOG}" || true
    redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_FILE}" || true
    break
  fi

  # Apply patch and commit
  if ! git apply --index "${PATCH_FILE}" 2> "${APPLY_ERR}"; then
    echo "git apply --index failed; see apply.err" | tee -a "${TEST_LOG}"
    cat "${APPLY_ERR}" >> "${TEST_LOG}" || true
    echo "=== AI RAW OUTPUT ===" >> "${TEST_LOG}"
    sed -n '1,400p' "${AI_RAW}" >> "${TEST_LOG}" || true
    redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_FILE}" || true
    break
  fi

  git add -A || true
  if git commit -m "chore: AI-assisted refactor and dependency update (iteration ${ITER})" >/dev/null 2>&1; then
    echo "Committed AI patch (iteration ${ITER})" | tee -a "${TEST_LOG}"
  else
    echo "No changes to commit after applying AI patch (iteration ${ITER})" | tee -a "${TEST_LOG}"
  fi

  # Run tests after applying patch
  if go test ./... 2>&1 | tee -a "${TEST_LOG}"; then
    echo "Tests passed after applying AI patch (iteration ${ITER})" | tee -a "${TEST_LOG}"
    PASS_ALL=true
    break
  else
    echo "Tests still failing after applying AI patch (iteration ${ITER}); next iteration" | tee -a "${TEST_LOG}"
  fi
done

# Final checks
gofmt -l . > "${TMP_ROOT}/gofmt.list" || true
go vet ./... >> "${LINTER_LOG}" 2>&1 || true
go test ./... >> "${TEST_LOG}" 2>&1 || true

# Decide whether to push and create PR: only if meaningful Go/module changes exist
# Ensure remote base is fetched
git fetch origin "${BASE_BRANCH}" --depth=1 >/dev/null 2>&1 || true

CHANGED_FILES="$(git diff --name-only "origin/${BASE_BRANCH}...HEAD" || true)"
if printf "%s\n" "${CHANGED_FILES}" | egrep -q '\.go$|(^|/)go\.mod$|(^|/)go\.sum$'; then
  echo "Detected Go/module changes to push:" | tee -a "${PUSH_LOG}"
  printf "%s\n" "${CHANGED_FILES}" | tee -a "${PUSH_LOG}"
  # Push branch
  if git push --set-upstream origin "${BRANCH_NAME}" > "${PUSH_LOG}" 2>&1; then
    echo "Pushed branch ${BRANCH_NAME}" | tee -a "${PUSH_LOG}"
    # Create PR via API
    PR_PAYLOAD="$(jq -n \
      --arg title "chore(deps): Automated dependency updates and AI refactor" \
      --arg head "${BRANCH_NAME}" \
      --arg base "${BASE_BRANCH}" \
      --arg body "Automated dependency updates and AI-driven refactor were applied by CI. Please review the changes." \
      '{title: $title, head: $head, base: $base, body: $body}')"
    HTTP_PR_STATUS="$(curl -sS -X POST "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls" \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "${PR_PAYLOAD}" -w "%{http_code}" -o "${TMP_ROOT}/pr_response.json" )" || true
    echo "PR create HTTP status: ${HTTP_PR_STATUS}" >> "${PUSH_LOG}" || true
  else
    echo "Failed to push branch ${BRANCH_NAME}; check push.log" | tee -a "${PUSH_LOG}"
    git --no-pager log -n 5 --oneline >> "${PUSH_LOG}" || true
  fi
else
  echo "No Go/module changes detected; skipping push and PR creation." | tee -a "${PUSH_LOG}"
fi

# Prepare artifacts in the original workspace (avoid cp same-file errors)
WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
mkdir -p "${WORKSPACE}"
copy_to_workspace() {
  local src="$1"
  local dst="$2"
  if [ ! -e "${src}" ]; then
    return 0
  fi
  if [ -e "${dst}" ]; then
    if cmp -s "${src}" "${dst}"; then
      return 0
    fi
  fi
  cp "${src}" "${dst}"
}

# Redact and copy request/response
if [ -s "${REQUEST_FILE}" ]; then
  redact_stream < "${REQUEST_FILE}" > "${TMP_ROOT}/ai-request-redacted.json" || true
  copy_to_workspace "${TMP_ROOT}/ai-request-redacted.json" "${WORKSPACE}/ai-request.json"
fi
if [ -s "${RESPONSE_TMP}" ]; then
  redact_stream < "${RESPONSE_TMP}" > "${TMP_ROOT}/ai-response-redacted.json" || true
  copy_to_workspace "${TMP_ROOT}/ai-response-redacted.json" "${WORKSPACE}/ai-response.json"
fi
copy_to_workspace "${PATCH_FILE}" "${WORKSPACE}/ai.patch"
copy_to_workspace "${AI_RAW}" "${WORKSPACE}/ai-response-raw.txt"
copy_to_workspace "${TEST_LOG}" "${WORKSPACE}/tests.log"
copy_to_workspace "${LINTER_LOG}" "${WORKSPACE}/linter.log"
copy_to_workspace "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"
copy_to_workspace "${PUSH_LOG}" "${WORKSPACE}/push.log"
copy_to_workspace "${HTTP_STATUS_FILE}" "${WORKSPACE}/http_status.txt"
if [ -e "${TMP_ROOT}/pr_response.json" ]; then
  redact_stream < "${TMP_ROOT}/pr_response.json" > "${WORKSPACE}/pr_response.json"
fi
if [ -e "${TMP_ROOT}/gofmt.list" ]; then
  copy_to_workspace "${TMP_ROOT}/gofmt.list" "${WORKSPACE}/gofmt.list"
fi

# Clean up
rm -rf "${TMP_ROOT}"

echo "ai_refactor.sh completed."
 
