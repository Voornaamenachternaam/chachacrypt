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

if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY not set"
  exit 1
fi

if [ -z "${GH_TOKEN:-}" ]; then
  echo "GH_TOKEN not set"
  exit 1
fi

for cmd in git go jq curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required command not found in PATH: $cmd" >&2
    exit 1
  fi
done

WORKSPACE_DIR="${GITHUB_WORKSPACE:-$(pwd)}"
TMP_ROOT="$(mktemp -d)"
REPO_DIR="${TMP_ROOT}/repo"
REQUEST_FILE="${WORKSPACE_DIR}/ai-request.json"
RESPONSE_FILE="${WORKSPACE_DIR}/ai-response.json"
PATCH_FILE="${WORKSPACE_DIR}/ai.patch"
TEST_LOG="${WORKSPACE_DIR}/tests.log"
LINTER_LOG="${WORKSPACE_DIR}/linter.log"
PRE_DIFF="${WORKSPACE_DIR}/pre-ai.diff"
PUSH_LOG="${WORKSPACE_DIR}/push.log"
AI_RAW="${WORKSPACE_DIR}/ai-response-raw.txt"

: > "${REQUEST_FILE}"
: > "${RESPONSE_FILE}"
: > "${PATCH_FILE}"
: > "${TEST_LOG}"
: > "${LINTER_LOG}"
: > "${PRE_DIFF}"
: > "${PUSH_LOG}"
: > "${AI_RAW}"

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

GIT_CLONE_URL="https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"

git clone --depth=1 --no-single-branch "${GIT_CLONE_URL}" "${REPO_DIR}"
cd "${REPO_DIR}"
git config user.name "ci-gemini-bot"
git config user.email "ci-gemini-bot@users.noreply.github.com"

if [ -f go.mod ]; then
  GO_VER_RAW="$(go version | awk '{print $3}')"
  GO_VER="${GO_VER_RAW#go}"
  CURRENT_GO_DIRECTIVE="$(awk '/^go [0-9]/ {print $2; exit}' go.mod || true)"
  if [ -n "$GO_VER" ] && [ "$CURRENT_GO_DIRECTIVE" != "$GO_VER" ]; then
    go mod edit -go="${GO_VER}" || true
  fi
fi

git add -A
git reset --hard HEAD

gitleaks_artifact_path="${WORKSPACE_DIR}/gitleaks.json"
if [ -f "${WORKSPACE_DIR}/gitleaks.json" ]; then
  cp "${WORKSPACE_DIR}/gitleaks.json" "${REPO_DIR}/.gitleaks.json" || true
fi

UPGRADE_LINES=$(go list -m -u -json all 2>/dev/null | jq -r 'select(.Update) | .Path + "@" + .Update.Version' || true)

if [ -z "$UPGRADE_LINES" ]; then
  echo "No available module updates detected."
  cd "${WORKSPACE_DIR}"
  rm -rf "${TMP_ROOT}"
  exit 0
fi

printf "%s\n" "$UPGRADE_LINES" > "${WORKSPACE_DIR}/candidate-upgrades.txt"

TMP_UPGRADES="$(mktemp)"
printf "%s\n" "$UPGRADE_LINES" > "$TMP_UPGRADES"

while IFS= read -r modver; do
  if [ -n "$modver" ]; then
    {
      echo "Running: go get ${modver}"
      go get "${modver}" 2>&1
    } >> "${LINTER_LOG}" 2>&1 || {
      echo "Warning: go get ${modver} failed; continuing" >> "${LINTER_LOG}" 2>&1
    }
  fi
done < "$TMP_UPGRADES"
rm -f "$TMP_UPGRADES"

go mod tidy >> "${LINTER_LOG}" 2>&1 || true

BRANCH_NAME="automated-deps-$(date -u +"%Y%m%dT%H%M%SZ")"
git checkout -b "${BRANCH_NAME}"

git add go.mod go.sum || true

git diff --staged --no-color > "${PRE_DIFF}" || true
if [ ! -s "${PRE_DIFF}" ]; then
  git diff --no-color > "${PRE_DIFF}" || true
fi

MAX_ITER=5
ITER=0
PASS_ALL=false

while [ $ITER -lt $MAX_ITER ]; do
  ITER=$((ITER + 1))
  echo "=== Iteration ${ITER} ===" | tee -a "${TEST_LOG}"

  GO_FMT_ERRORS="$(gofmt -l . || true)"
  if [ -n "$GO_FMT_ERRORS" ]; then
    echo "gofmt reformatting..." | tee -a "${LINTER_LOG}"
    gofmt -w .
    git add -A
  fi

  echo "Running go vet..." | tee -a "${TEST_LOG}"
  if go vet ./... 2>&1 | tee -a "${TEST_LOG}"; then
    echo "go vet OK" | tee -a "${TEST_LOG}"
  else
    echo "go vet reported issues" | tee -a "${TEST_LOG}"
  fi

  echo "Running go test..." | tee -a "${TEST_LOG}"
  if go test ./... 2>&1 | tee -a "${TEST_LOG}"; then
    echo "All tests passed on iteration ${ITER}." | tee -a "${TEST_LOG}"
    PASS_ALL=true
    break
  else
    echo "Tests failed on iteration ${ITER}." | tee -a "${TEST_LOG}"
  fi

  STAGED_DIFF="$(git diff --staged --no-color || true)"
  WORKING_DIFF="$(git diff --no-color || true)"
  DIFF_TO_SEND="${STAGED_DIFF:-${WORKING_DIFF}}"
  if [ -z "${DIFF_TO_SEND}" ]; then
    echo "No diff found to repair; aborting AI loop." | tee -a "${TEST_LOG}"
    break
  fi

  FAIL_SNIPPET="$(tail -n 800 "${TEST_LOG}" || true)"
  {
    printf "%s\n\n%s\n\n%s\n" \
      "TASK: Create a single unified git patch (unified diff starting with 'diff --git') that updates the repository source code so that all 'go test ./...' pass, and all 'go vet' and 'gofmt' issues are resolved. Only modify Go source files and module files as necessary. Do not include extra commentary. Output exactly one unified diff and nothing else. Wrap the unified diff starting with 'diff --git' (no additional prefixes)." \
      "FAILING_TESTS_OUTPUT (excerpt):" \
      "$FAIL_SNIPPET"
    printf "\n---BEGIN_DIFF---\n%s\n---END_DIFF---\n" "$DIFF_TO_SEND"
  } > "${TMP_ROOT}/sendable-context.tmp"

  redact < "${TMP_ROOT}/sendable-context.tmp" > "${TMP_ROOT}/sendable-context.redacted.tmp" || true
  PROMPT_CONTENT="$(sed 's/\\/\\\\/g; s/"/\\"/g' "${TMP_ROOT}/sendable-context.redacted.tmp")"

  build_payload "$PROMPT_CONTENT" > "${REQUEST_FILE}"

  HTTP_RESPONSE=$(curl -sS -X POST "${API_URL}" \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    --data-binary @"${REQUEST_FILE}" -w "\n%{http_code}" || true)

  HTTP_BODY="$(printf "%s" "$HTTP_RESPONSE" | sed '$d')"
  HTTP_STATUS="$(printf "%s" "$HTTP_RESPONSE" | tail -n1)"
  printf "%s" "$HTTP_BODY" > "${RESPONSE_FILE}"
  echo "HTTP status: ${HTTP_STATUS}" | tee -a "${TEST_LOG}"

  redact < "${RESPONSE_FILE}" > "${RESPONSE_FILE}.redacted" || true

  AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // .result[0].content[0].text // empty' "${RESPONSE_FILE}" 2>/dev/null || true)"
  if [ -z "${AI_CONTENT}" ]; then
    AI_CONTENT="$(cat "${RESPONSE_FILE}")"
  fi

  printf "%s" "${AI_CONTENT}" > "${AI_RAW}"

  printf "%s\n" "${AI_CONTENT}" | sed -n '/^diff --git /,$p' > "${PATCH_FILE}" || true

  if [ ! -s "${PATCH_FILE}" ]; then
    echo "AI did not return a unified diff starting with 'diff --git'. Aborting AI loop." | tee -a "${TEST_LOG}"
    cat "${AI_RAW}" >> "${TEST_LOG}" || true
    break
  fi

  set +e
  git apply --index "${PATCH_FILE}" 2> "${TMP_ROOT}/apply.err"
  APPLY_EXIT=$?
  set -e

  if [ ${APPLY_EXIT} -ne 0 ]; then
    echo "git apply failed; saving apply.err and aborting AI loop." | tee -a "${TEST_LOG}"
    cat "${TMP_ROOT}/apply.err" >> "${TEST_LOG}" || true
    cat "${AI_RAW}" >> "${TEST_LOG}" || true
    break
  fi

  git add -A
  git commit -m "chore: ai automated refactor for dependency upgrades (iteration ${ITER})" || true

done

gofmt -l . > /dev/null 2>&1 || true
go vet ./... 2>&1 | tee -a "${TEST_LOG}" || true
go test ./... 2>&1 | tee -a "${TEST_LOG}" || true || true

echo "Attempting to push changes to remote..." | tee -a "${PUSH_LOG}"
set +e
git push --set-upstream origin "${BRANCH_NAME}" 2>&1 | tee -a "${PUSH_LOG}"
PUSH_EXIT=${PIPESTATUS[0]}
set -e

if [ ${PUSH_EXIT} -ne 0 ]; then
  PR_PAYLOAD=$(jq -n \
    --arg head "${BRANCH_NAME}" \
    --arg base "${DEFAULT_BRANCH}" \
    --arg title "chore(deps): Automated dependency update and AI refactor" \
    --arg body "Automated dependency updates applied and refactored by CI_Grok4. Tests and linters were run in CI. This PR was opened by automation." \
    '{title:$title, head:$head, base:$base, body:$body}')
  PR_RESPONSE=$(curl -sS -X POST "https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls" \
    -H "Authorization: token ${GH_TOKEN}" \
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

redact < "${REQUEST_FILE}" > "${REQUEST_FILE}.redacted" || true
redact < "${RESPONSE_FILE}" > "${RESPONSE_FILE}.redacted" || true

cp -f "${REQUEST_FILE}.redacted" "${WORKSPACE_DIR}/ai-request.json" || true
cp -f "${RESPONSE_FILE}.redacted" "${WORKSPACE_DIR}/ai-response.json" || true
cp -f "${PATCH_FILE}" "${WORKSPACE_DIR}/ai.patch" || true
cp -f "${TEST_LOG}" "${WORKSPACE_DIR}/tests.log" || true
cp -f "${LINTER_LOG}" "${WORKSPACE_DIR}/linter.log" || true
cp -f "${PRE_DIFF}" "${WORKSPACE_DIR}/pre-ai.diff" || true
cp -f "${PUSH_LOG}" "${WORKSPACE_DIR}/push.log" || true
cp -f "${AI_RAW}" "${WORKSPACE_DIR}/ai-response-raw.txt" || true

cd "${WORKSPACE_DIR}"
rm -rf "${TMP_ROOT}"

echo "ai_refactor.sh completed."
