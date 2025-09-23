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

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

# Verify required commands are available
for c in git go jq curl sed awk cmp mktemp mkdir date tee awk; do
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "Required command not found in PATH: $c" >&2
    exit 1
  fi
done

# Redaction helper for artifacts
redact_stream() {
  sed -E \
    -e 's/(Authorization: Bearer )[A-Za-z0-9._-]+/\1REDACTED_TOKEN/g' \
    -e 's/"openai_api_key"[[:space:]]*:[[:space:]]*"[^"]*"/"openai_api_key":"REDACTED_TOKEN"/g' \
    -e 's/"api_key"[[:space:]]*:[[:space:]]*"[^"]*"/"api_key":"REDACTED_TOKEN"/g' \
    -e 's/[A-Za-z0-9_-]{20,}[A-Za-z0-9._+-\/=]{10,}/REDACTED_TOKEN/g' \
    -e '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/c\[REDACTED PRIVATE KEY\]'
}

# Create temp workspace & files
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

REQUEST_FILE="${TMP_ROOT}/ai-request.json"
RESPONSE_TMP="${TMP_ROOT}/ai-response.tmp"
RESPONSE_REDACTED="${TMP_ROOT}/ai-response-redacted.json"
AI_RAW="${TMP_ROOT}/ai-response-raw.txt"
PATCH_FILE="${TMP_ROOT}/ai.patch"
APPLY_ERR="${TMP_ROOT}/apply.err"
BUILD_LOG="${TMP_ROOT}/build.log"
LINTER_LOG="${TMP_ROOT}/linter.log"
PRE_DIFF_TMP="${TMP_ROOT}/pre-ai.diff"
PUSH_LOG="${TMP_ROOT}/push.log"
HTTP_STATUS_FILE="${TMP_ROOT}/http_status.txt"
GOFMT_LIST="${TMP_ROOT}/gofmt.list"
PR_RESPONSE="${TMP_ROOT}/pr_response.json"

: > "${REQUEST_FILE}"
: > "${RESPONSE_TMP}"
: > "${RESPONSE_REDACTED}"
: > "${AI_RAW}"
: > "${PATCH_FILE}"
: > "${APPLY_ERR}"
: > "${BUILD_LOG}"
: > "${LINTER_LOG}"
: > "${PRE_DIFF_TMP}"
: > "${PUSH_LOG}"
: > "${HTTP_STATUS_FILE}"
: > "${GOFMT_LIST}"
: > "${PR_RESPONSE}"

# Clone repo into temp dir to avoid mutating workspace directly
REPO_CLONE_DIR="${TMP_ROOT}/repo"
git clone --depth=1 --no-single-branch "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "${REPO_CLONE_DIR}"
cd "${REPO_CLONE_DIR}"

git config user.name "ci-grok4-bot"
git config user.email "ci-grok4-bot@users.noreply.github.com"

BASE_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
BRANCH_NAME="automated-deps-$(date -u +"%Y%m%dT%H%M%SZ")"
git checkout -b "${BRANCH_NAME}"
echo "Switched to new branch ${BRANCH_NAME} (base ${BASE_BRANCH})"

# Keep go.mod go directive aligned with runtime
if [ -f go.mod ]; then
  GO_VER_RAW="$(go version | awk '{print $3}')"
  GO_VER="${GO_VER_RAW#go}"
  CURRENT_GO_DIRECTIVE="$(awk '/^go [0-9]/ {print $2; exit}' go.mod || true)"
  if [ -n "${GO_VER}" ] && [ "${CURRENT_GO_DIRECTIVE}" != "${GO_VER}" ]; then
    echo "Updating go.mod go directive ${CURRENT_GO_DIRECTIVE} -> ${GO_VER}" | tee -a "${LINTER_LOG}"
    go mod edit -go="${GO_VER}" || true
    git add go.mod || true
  fi
fi

# Capture pre-AI diff for artifact
git add -A || true
git diff --staged --no-color > "${PRE_DIFF_TMP}" || true
if [ ! -s "${PRE_DIFF_TMP}" ]; then
  git diff --no-color > "${PRE_DIFF_TMP}" || true
fi

# Payload builder with OpenRouter reasoning enabled
build_payload() {
  local system_msg="$1"
  local user_msg="$2"
  jq -n --arg model "$AI_MODEL" --arg system "$system_msg" --arg user "$user_msg" \
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

# Extract unified diff robustly (handles fences)
extract_unified_diff() {
  local srcfile="$1"
  local out="$2"
  if grep -q '^diff --git ' -- "$srcfile" 2>/dev/null; then
    sed -n '/^diff --git /,$p' "$srcfile" > "$out"
    [ -s "$out" ] && return 0
  fi
  if grep -q '^```' -- "$srcfile" 2>/dev/null; then
    awk 'BEGIN{f=0} /^```/{f=!f; next} f{print}' "$srcfile" | sed -n '/^diff --git /,$p' > "$out"
    [ -s "$out" ] && return 0
  fi
  awk 'BEGIN{f=0} /^@@ |^--- |^\+\+\+ |^diff --git /{f=1} f{print}' "$srcfile" > "$out"
  [ -s "$out" ] && return 0
  return 1
}

# If mode is dependencies, detect module updates and attempt go get
if [ "${MODE}" = "dependencies" ]; then
  # Use jq safely to list updates
  UPGRADE_LINES="$(go list -m -u -json all 2>/dev/null | jq -r 'select(.Update) | "\(.Path)@\(.Update.Version)"' 2>/dev/null || true)"
  if [ -z "${UPGRADE_LINES}" ]; then
    # Save pre-ai diff to workspace for artifacts and exit (no updates)
    WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
    mkdir -p "${WORKSPACE}"
    if [ -s "${PRE_DIFF_TMP}" ]; then
      if [ ! -e "${WORKSPACE}/pre-ai.diff" ] || ! cmp -s "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"; then
        cp "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"
      fi
    fi
    exit 0
  fi

  # Attempt each upgrade (best-effort)
  printf "%s\n" "${UPGRADE_LINES}" | while IFS= read -r m; do
    if [ -n "${m}" ]; then
      echo "Attempting go get ${m}" | tee -a "${LINTER_LOG}"
      GOFLAGS=-mod=mod go get -d "${m}" >> "${LINTER_LOG}" 2>&1 || true
    fi
  done
  go mod tidy >> "${LINTER_LOG}" 2>&1 || true
  git add go.mod go.sum 2>/dev/null || true
fi

# Refresh pre-AI diff after updates
git diff --staged --no-color > "${PRE_DIFF_TMP}" || true
if [ ! -s "${PRE_DIFF_TMP}" ]; then
  git diff --no-color > "${PRE_DIFF_TMP}" || true
fi

# Decide whether we need AI: run go build to detect compile errors (no tests assumed)
echo "Running go build to detect compile errors..." | tee -a "${BUILD_LOG}"
if go build ./... >> "${BUILD_LOG}" 2>&1; then
  BUILD_FAILED=false
else
  BUILD_FAILED=true
fi

# If build passed and no other needs, commit go.mod/go.sum if changed and create PR
if [ "${BUILD_FAILED}" = false ]; then
  # Check for meaningful Go/module changes
  git fetch origin "${BASE_BRANCH}" --depth=1 >/dev/null 2>&1 || true
  CHANGED_FILES="$(git diff --name-only "origin/${BASE_BRANCH}...HEAD" || true)"
  if printf "%s\n" "${CHANGED_FILES}" | egrep -q '\.go$|(^|/)go\.mod$|(^|/)go\.sum$'; then
    # push & create PR
    if git push --set-upstream origin "${BRANCH_NAME}" > "${PUSH_LOG}" 2>&1; then
      PR_PAYLOAD="$(jq -n --arg title "chore(deps): Automated dependency updates and AI refactor" \
        --arg head "${BRANCH_NAME}" --arg base "${BASE_BRANCH}" \
        --arg body "Automated dependency updates and AI-driven refactor were applied by CI. Please review the changes." \
        '{title: $title, head: $head, base: $base, body: $body}')"
      curl -sS -X POST "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls" \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${PR_PAYLOAD}" -o "${PR_RESPONSE}" -w "%{http_code}" > "${TMP_ROOT}/pr_http_status.txt" || true
    else
      echo "Push failed; please inspect ${PUSH_LOG}" | tee -a "${PUSH_LOG}"
    fi
  else
    # No meaningful changes: copy pre-ai diff and exit
    WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
    mkdir -p "${WORKSPACE}"
    if [ -s "${PRE_DIFF_TMP}" ]; then
      if [ ! -e "${WORKSPACE}/pre-ai.diff" ] || ! cmp -s "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"; then
        cp "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"
      fi
    fi
    exit 0
  fi
fi

# Build failed: capture error output and invoke AI to fix compile errors
if [ "${BUILD_FAILED}" = true ]; then
  # Prepare failing build output (last 2000 lines at most)
  tail -n 2000 "${BUILD_LOG}" > "${TMP_ROOT}/build-fail-snippet.txt" || true
  FAIL_SNIPPET="$(cat "${TMP_ROOT}/build-fail-snippet.txt" || true)"

  # Iteratively request AI-generated patches and apply until build passes or max iterations
  MAX_ITER=5
  ITER=0
  while [ "${ITER}" -lt "${MAX_ITER}" ]; do
    ITER=$((ITER + 1))
    echo "=== AI Iteration ${ITER} ===" | tee -a "${BUILD_LOG}"

    # Prepare diff to send
    DIFF_FILE="${TMP_ROOT}/diff-to-send.patch"
    git add -A || true
    git diff --staged --no-color > "${DIFF_FILE}" || true
    if [ ! -s "${DIFF_FILE}" ]; then
      git diff --no-color > "${DIFF_FILE}" || true
    fi
    if [ ! -s "${DIFF_FILE}" ]; then
      echo "No diff available to send to AI; aborting" | tee -a "${BUILD_LOG}"
      break
    fi

    TASK_INSTR="You are an expert Go engineer. Given the following compiler/build errors and the repository diff, produce a single unified git patch (a unified diff starting with 'diff --git') that fixes the compiler errors and allows the project to build. Return only the unified patch, and nothing else. If you cannot produce a working patch, return an empty response."
    PROMPT_CONTENT="$(printf "%s\n\n=== BUILD ERRORS ===\n%s\n\n=== REPO DIFF ===\n%s\n" "${TASK_INSTR}" "${FAIL_SNIPPET}" "$(sed -n '1,20000p' "${DIFF_FILE}" || true)")"

    # Build and save payload
    build_payload "${TASK_INSTR}" "${PROMPT_CONTENT}" > "${REQUEST_FILE}"
    redact_stream < "${REQUEST_FILE}" > "${TMP_ROOT}/ai-request-redacted.json" || true

    # Send request and capture HTTP status + raw body
    HTTP_CODE="$(curl -sS -X POST "${API_URL}" \
      -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
      -H "Content-Type: application/json" \
      -d @"${REQUEST_FILE}" \
      -w "%{http_code}" -o "${RESPONSE_TMP}" )" || true

    echo "${HTTP_CODE}" > "${HTTP_STATUS_FILE}"
    cat "${RESPONSE_TMP}" > "${AI_RAW}" || true

    if [ -z "${HTTP_CODE}" ] || [ "${HTTP_CODE}" -lt 200 ] || [ "${HTTP_CODE}" -ge 300 ]; then
      redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_REDACTED}" || true
      echo "AI API returned HTTP ${HTTP_CODE}; aborting AI loop" | tee -a "${BUILD_LOG}" "${LINTER_LOG}"
      break
    fi

    # Extract AI content
    if jq -e . >/dev/null 2>&1 < "${RESPONSE_TMP}"; then
      AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // ""' "${RESPONSE_TMP}" 2>/dev/null || true)"
    else
      AI_CONTENT="$(cat "${RESPONSE_TMP}" || true)"
    fi

    printf "%s\n" "${AI_CONTENT}" > "${AI_RAW}"

    # Extract unified diff from AI response
    if ! extract_unified_diff "${AI_RAW}" "${PATCH_FILE}"; then
      redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_REDACTED}" || true
      echo "AI did not produce a valid unified diff; aborting AI loop" | tee -a "${BUILD_LOG}"
      break
    fi

    # Validate patch can be applied
    if ! git apply --check "${PATCH_FILE}" 2> "${APPLY_ERR}"; then
      cat "${APPLY_ERR}" >> "${BUILD_LOG}" || true
      redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_REDACTED}" || true
      echo "git apply --check failed; aborting AI loop" | tee -a "${BUILD_LOG}"
      break
    fi

    # Apply patch
    if ! git apply --index "${PATCH_FILE}" 2> "${APPLY_ERR}"; then
      cat "${APPLY_ERR}" >> "${BUILD_LOG}" || true
      redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_REDACTED}" || true
      echo "git apply --index failed; aborting AI loop" | tee -a "${BUILD_LOG}"
      break
    fi

    git add -A || true
    if git commit -m "chore: AI-assisted refactor and dependency update (iteration ${ITER})" >/dev/null 2>&1; then
      echo "Committed AI patch (iteration ${ITER})" | tee -a "${BUILD_LOG}"
    else
      echo "No changes to commit after applying AI patch (iteration ${ITER})" | tee -a "${BUILD_LOG}"
    fi

    # Re-run build
    : > "${BUILD_LOG}"
    echo "Re-running go build after applying AI patch..." | tee -a "${BUILD_LOG}"
    if go build ./... >> "${BUILD_LOG}" 2>&1; then
      echo "Build succeeded after iteration ${ITER}" | tee -a "${BUILD_LOG}"
      BUILD_FAILED=false
      break
    else
      echo "Build still failing after iteration ${ITER}; will iterate again" | tee -a "${BUILD_LOG}"
      FAIL_SNIPPET="$(tail -n 2000 "${BUILD_LOG}" || true)"
      continue
    fi
  done
fi

# Final lint/format checks
gofmt -l . > "${GOFMT_LIST}" || true
go vet ./... >> "${LINTER_LOG}" 2>&1 || true
# final build attempt (ensure success if possible)
if go build ./... >> "${BUILD_LOG}" 2>&1; then
  BUILD_FAILED=false
else
  BUILD_FAILED=true
fi

# Push & PR only if meaningful Go/module changes exist and build is not failing
git fetch origin "${BASE_BRANCH}" --depth=1 >/dev/null 2>&1 || true
CHANGED_FILES="$(git diff --name-only "origin/${BASE_BRANCH}...HEAD" || true)"

if [ "${BUILD_FAILED}" = false ] && printf "%s\n" "${CHANGED_FILES}" | egrep -q '\.go$|(^|/)go\.mod$|(^|/)go\.sum$'; then
  git push --set-upstream origin "${BRANCH_NAME}" > "${PUSH_LOG}" 2>&1 || true
  PR_PAYLOAD="$(jq -n --arg title "chore(deps): Automated dependency updates and AI refactor" \
    --arg head "${BRANCH_NAME}" --arg base "${BASE_BRANCH}" \
    --arg body "Automated dependency updates and AI-driven refactor were applied by CI. Please review the changes." \
    '{title: $title, head: $head, base: $base, body: $body}')"
  curl -sS -X POST "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls" \
    -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${PR_PAYLOAD}" -o "${PR_RESPONSE}" -w "%{http_code}" > "${TMP_ROOT}/pr_http_status.txt" || true
else
  echo "Skipping push/PR: either build failing or no meaningful Go/module changes." | tee -a "${PUSH_LOG}"
fi

# Copy artifacts into workspace for workflow to upload (do not commit these)
WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
mkdir -p "${WORKSPACE}"

copy_to_workspace() {
  local src="$1"
  local dst="$2"
  if [ ! -e "${src}" ]; then
    return 0
  fi
  if [ -e "${dst}" ] && cmp -s "${src}" "${dst}" 2>/dev/null; then
    return 0
  fi
  cp "${src}" "${dst}"
}

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
copy_to_workspace "${BUILD_LOG}" "${WORKSPACE}/build.log"
copy_to_workspace "${LINTER_LOG}" "${WORKSPACE}/linter.log"
copy_to_workspace "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"
copy_to_workspace "${PUSH_LOG}" "${WORKSPACE}/push.log"
copy_to_workspace "${HTTP_STATUS_FILE}" "${WORKSPACE}/http_status.txt"
copy_to_workspace "${GOFMT_LIST}" "${WORKSPACE}/gofmt.list"
if [ -e "${PR_RESPONSE}" ]; then
  redact_stream < "${PR_RESPONSE}" > "${TMP_ROOT}/pr_response_redacted.json" || true
  copy_to_workspace "${TMP_ROOT}/pr_response_redacted.json" "${WORKSPACE}/pr_response.json"
fi

exit 0
