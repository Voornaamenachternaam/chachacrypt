#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
API_URL="${2:-}"
AI_MODEL="${3:-}"

if [ -z "${MODE}" ] || [ -z "${API_URL}" ] || [ -z "${AI_MODEL}" ]; then
  echo "Usage: $0 <mode> <api_url> <ai_model>"
  exit 1
fi

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

ensure_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -y >/dev/null 2>&1 || true
      sudo apt-get install -y "$2" >/dev/null 2>&1 || true
    fi
  fi
}

ensure_cmd git git
ensure_cmd go golang-go
ensure_cmd curl curl
ensure_cmd jq jq
ensure_cmd sed sed
ensure_cmd awk awk
ensure_cmd cmp diffutils
ensure_cmd mktemp mktemp
ensure_cmd mkdir coreutils
ensure_cmd date coreutils
ensure_cmd git git

redact_stream() {
  sed -E \
    -e 's/(Authorization: Bearer )[A-Za-z0-9._-]+/\1REDACTED_TOKEN/g' \
    -e 's/"openai_api_key"[[:space:]]*:[[:space:]]*"[^"]*"/"openai_api_key":"REDACTED_TOKEN"/g' \
    -e 's/"api_key"[[:space:]]*:[[:space:]]*"[^"]*"/"api_key":"REDACTED_TOKEN"/g' \
    -e 's/[A-Za-z0-9_-]\{20,\}[A-Za-z0-9._+-\/=]\{20,\}/REDACTED_TOKEN/g' \
    -e '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/c\[REDACTED PRIVATE KEY\]'
}

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

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
GOFMT_LIST="${TMP_ROOT}/gofmt.list"
PR_RESPONSE="${TMP_ROOT}/pr_response.json"

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
: > "${GOFMT_LIST}"
: > "${PR_RESPONSE}"

REPO_CLONE_DIR="${TMP_ROOT}/repo"
git clone --depth=1 --no-single-branch "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "${REPO_CLONE_DIR}"
cd "${REPO_CLONE_DIR}"

git config user.name "ci-grok4-bot"
git config user.email "ci-grok4-bot@users.noreply.github.com"

BASE_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
BRANCH_NAME="automated-deps-$(date -u +"%Y%m%dT%H%M%SZ")"
git checkout -b "${BRANCH_NAME}"

if [ -f go.mod ]; then
  GO_VER_RAW="$(go version | awk '{print $3}')"
  GO_VER="${GO_VER_RAW#go}"
  CURRENT_GO_DIRECTIVE="$(awk '/^go [0-9]/ {print $2; exit}' go.mod || true)
  if [ -n "${GO_VER}" ] && [ "${CURRENT_GO_DIRECTIVE}" != "${GO_VER}" ]; then
    go mod edit -go="${GO_VER}" || true
    git add go.mod || true
  fi
fi

git add -A || true
git diff --staged --no-color > "${PRE_DIFF_TMP}" || true
if [ ! -s "${PRE_DIFF_TMP}" ]; then
  git diff --no-color > "${PRE_DIFF_TMP}" || true
fi

build_payload() {
  local system_msg="$1"
  local user_msg="$2"
  jq -n --arg model "$AI_MODEL" --arg system "$system_msg" --arg user "$user_msg" \
    '{
      model: $model,
      messages: [{ role: "system", content: $system }, { role: "user", content: $user }],
      temperature: 0.0,
      max_tokens: 32768,
      include_reasoning: true,
      reasoning: { effort: "high" }
    }'
}

extract_unified_diff() {
  local srcfile="$1"
  local out="$2"
  if grep -q '^diff --git ' "${srcfile}"; then
    sed -n '/^diff --git /,$p' "${srcfile}" > "${out}"
    [ -s "${out}" ] && return 0
  fi
  if grep -q '^```' "${srcfile}"; then
    awk 'BEGIN{f=0} /^```/{f=!f; next} f{print}' "${srcfile}" | sed -n '/^diff --git /,$p' > "${out}"
    [ -s "${out}" ] && return 0
  fi
  awk 'BEGIN{f=0} /^@@ |^--- |^\+\+\+ |^diff --git /{f=1} f{print}' "${srcfile}" > "${out}"
  [ -s "${out}" ] && return 0
  return 1
}

if [ "${MODE}" = "dependencies" ]; then
  UPGRADE_LINES="$(go list -m -u -json all 2>/dev/null | jq -r 'select(.Update) | "\(.Path)@\(.Update.Version)"' 2>/dev/null || true)"
  if [ -z "${UPGRADE_LINES}" ]; then
    WORKSPACE="${GITHUB_WORKSPACE:-/github/workspace}"
    mkdir -p "${WORKSPACE}"
    if [ -s "${PRE_DIFF_TMP}" ]; then
      if [ ! -e "${WORKSPACE}/pre-ai.diff" ] || ! cmp -s "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"; then
        cp "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"
      fi
    fi
    exit 0
  fi

  while IFS= read -r m; do
    if [ -n "${m}" ]; then
      GOFLAGS=-mod=mod go get -d "${m}" >> "${LINTER_LOG}" 2>&1 || true
    fi
  done <<< "${UPGRADE_LINES}"
  go mod tidy >> "${LINTER_LOG}" 2>&1 || true
  git add go.mod go.sum 2>/dev/null || true
fi

git diff --staged --no-color > "${PRE_DIFF_TMP}" || true
if [ ! -s "${PRE_DIFF_TMP}" ]; then
  git diff --no-color > "${PRE_DIFF_TMP}" || true
fi

MAX_ITER=5
ITER=0
PASS_ALL=false

while [ "${ITER}" -lt "${MAX_ITER}" ]; do
  ITER=$((ITER + 1))
  GOFMT_LIST="$(gofmt -l . || true)"
  if [ -n "${GOFMT_LIST}" ]; then
    gofmt -w .
    git add -A || true
  fi

  go vet ./... >> "${LINTER_LOG}" 2>&1 || true

  if go test ./... 2>&1 | tee -a "${TEST_LOG}"; then
    PASS_ALL=true
    break
  fi

  DIFF_FILE="${TMP_ROOT}/diff-to-send.patch"
  git add -A || true
  git diff --staged --no-color > "${DIFF_FILE}" || true
  if [ ! -s "${DIFF_FILE}" ]; then
    git diff --no-color > "${DIFF_FILE}" || true
  fi
  if [ ! -s "${DIFF_FILE}" ]; then
    break
  fi

  FAIL_SNIPPET="$(tail -n 800 "${TEST_LOG}" || true)"
  TASK_INSTR="You are an expert Go engineer. Given the failing test output and the following repository diff, produce a single unified git patch (a unified diff starting with 'diff --git') that fixes the failing tests and compiles cleanly. Return only the unified patch (no additional commentary). If you cannot produce a working patch, return an empty response."
  PROMPT_CONTENT="$(printf "%s\n\n=== FAILING TEST OUTPUT ===\n%s\n\n=== REPO DIFF ===\n%s\n" "${TASK_INSTR}" "${FAIL_SNIPPET}" "$(sed -n '1,2000p' "${DIFF_FILE}" || true)")"

  build_payload "$TASK_INSTR" "$PROMPT_CONTENT" > "${REQUEST_FILE}"

  HTTP_CODE="$(curl -sS -X POST "${API_URL}" \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    -d @"${REQUEST_FILE}" \
    -w "%{http_code}" -o "${RESPONSE_TMP}" )" || true

  echo "${HTTP_CODE}" > "${HTTP_STATUS_FILE}"
  cat "${RESPONSE_TMP}" > "${AI_RAW}" || true

  if [ -z "${HTTP_CODE}" ] || [ "${HTTP_CODE}" -lt 200 ] || [ "${HTTP_CODE}" -ge 300 ]; then
    redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_FILE}" || true
    break
  fi

  if jq -e . >/dev/null 2>&1 < "${RESPONSE_TMP}"; then
    AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // empty' "${RESPONSE_TMP}" 2>/dev/null || true)"
  else
    AI_CONTENT="$(cat "${RESPONSE_TMP}" || true)"
  fi

  printf "%s\n" "${AI_CONTENT}" > "${AI_RAW}"

  if ! extract_unified_diff "${AI_RAW}" "${PATCH_FILE}"; then
    redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_FILE}" || true
    break
  fi

  if ! git apply --check "${PATCH_FILE}" 2> "${APPLY_ERR}"; then
    cat "${APPLY_ERR}" >> "${TEST_LOG}" || true
    redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_FILE}" || true
    break
  fi

  if ! git apply --index "${PATCH_FILE}" 2> "${APPLY_ERR}"; then
    cat "${APPLY_ERR}" >> "${TEST_LOG}" || true
    redact_stream < "${RESPONSE_TMP}" > "${RESPONSE_FILE}" || true
    break
  fi

  git add -A || true
  if git commit -m "chore: AI-assisted refactor and dependency update (iteration ${ITER})" >/dev/null 2>&1; then
    :
  fi

  if go test ./... 2>&1 | tee -a "${TEST_LOG}"; then
    PASS_ALL=true
    break
  fi
done

gofmt -l . > "${GOFMT_LIST}" || true
go vet ./... >> "${LINTER_LOG}" 2>&1 || true
go test ./... >> "${TEST_LOG}" 2>&1 || true

git fetch origin "${BASE_BRANCH}" --depth=1 >/dev/null 2>&1 || true
CHANGED_FILES="$(git diff --name-only "origin/${BASE_BRANCH}...HEAD" || true)"

if printf "%s\n" "${CHANGED_FILES}" | egrep -q '\.go$|(^|/)go\.mod$|(^|/)go\.sum$'; then
  git push --set-upstream origin "${BRANCH_NAME}" > "${PUSH_LOG}" 2>&1 || true
  PR_PAYLOAD="$(jq -n --arg title "chore(deps): Automated dependency updates and AI refactor" --arg head "${BRANCH_NAME}" --arg base "${BASE_BRANCH}" --arg body "Automated dependency updates and AI-driven refactor were applied by CI. Please review the changes." '{title: $title, head: $head, base: $base, body: $body}')"
  HTTP_PR_STATUS="$(curl -sS -X POST "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls" -H "Authorization: token ${GITHUB_TOKEN}" -H "Content-Type: application/json" -d "${PR_PAYLOAD}" -w "%{http_code}" -o "${PR_RESPONSE}" )" || true
  echo "${HTTP_PR_STATUS}" >> "${PUSH_LOG}" || true
fi

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
copy_to_workspace "${TEST_LOG}" "${WORKSPACE}/tests.log"
copy_to_workspace "${LINTER_LOG}" "${WORKSPACE}/linter.log"
copy_to_workspace "${PRE_DIFF_TMP}" "${WORKSPACE}/pre-ai.diff"
copy_to_workspace "${PUSH_LOG}" "${WORKSPACE}/push.log"
copy_to_workspace "${HTTP_STATUS_FILE}" "${WORKSPACE}/http_status.txt"
copy_to_workspace "${GOFMT_LIST}" "${WORKSPACE}/gofmt.list"
if [ -e "${PR_RESPONSE}" ]; then
  redact_stream < "${PR_RESPONSE}" > "${WORKSPACE}/pr_response.json" || true
fi

exit 0
 
