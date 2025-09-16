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

command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 1; }
command -v gitleaks >/dev/null 2>&1 || { echo "gitleaks required"; exit 1; }
command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint required"; exit 1; }

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

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is not clean. Please run on a clean workspace."
  git status --porcelain
  exit 1
fi

BASE_COMMIT="$(git rev-parse --verify HEAD)"
DEFAULT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

if [ -f go.mod ]; then
  GO_VER="$(go version | awk '{print $3}' | sed 's/go//')"
  CURRENT_GO_DIRECTIVE="$(awk '/^go [0-9]/ {print $2; exit}' go.mod || true)"
  if [ -n "$GO_VER" ] && [ "$CURRENT_GO_DIRECTIVE" != "$GO_VER" ]; then
    go mod edit -go="${GO_VER}" || true
  fi
fi

gitleaks detect --report-path="${GITLEAKS_LOG}" || true

UPGRADE_LINES=$(go list -m -u -json all 2>/dev/null | jq -r 'select(.Update) | .Path + "@" + .Update.Version' || true)

if [ -z "$UPGRADE_LINES" ]; then
  echo "No available module updates detected."
  exit 0
fi

TMP_UPGRADES="$(mktemp)"
printf "%s\n" "$UPGRADE_LINES" > "$TMP_UPGRADES"

while IFS= read -r modver; do
  if [ -n "$modver" ]; then
    echo "Running: go get ${modver}"
    if ! go get "${modver}"; then
      echo "Warning: go get ${modver} failed, continuing" >&2
    fi
  fi
done < "$TMP_UPGRADES"
rm -f "$TMP_UPGRADES"

go mod tidy

BRANCH_NAME="automated-deps-$(date -u +"%Y%m%dT%H%M%SZ")"
git checkout -b "${BRANCH_NAME}"

git add go.mod go.sum || true

git diff --staged --no-color > pre-ai.diff || true
if [ ! -s pre-ai.diff ]; then
  git diff --no-color > pre-ai.diff || true
fi

MAX_ITER=5
ITER=0
PASS_ALL=false

while [ $ITER -lt $MAX_ITER ]; do
  ITER=$((ITER + 1))
  echo "=== Iteration ${ITER} ==="

  echo "Running gofmt check..." | tee -a "${LINTER_LOG}"
  GO_FMT_ERRORS="$(gofmt -l . || true)"
  if [ -n "$GO_FMT_ERRORS" ]; then
    echo "gofmt suggested changes for following files:" | tee -a "${LINTER_LOG}"
    echo "$GO_FMT_ERRORS" | tee -a "${LINTER_LOG}"
    gofmt -w .
  fi

  echo "Running golangci-lint..." | tee -a "${LINTER_LOG}"
  golangci-lint run ./... 2>&1 | tee -a "${LINTER_LOG}" || true

  echo "Running go vet..." | tee -a "${TEST_LOG}"
  go vet ./... 2>&1 | tee -a "${TEST_LOG}" || true

  echo "Running go test..." | tee -a "${TEST_LOG}"
  if go test ./... 2>&1 | tee -a "${TEST_LOG}"; then
    echo "All tests passed on iteration ${ITER}."
    PASS_ALL=true
    break
  else
    echo "Tests failed on iteration ${ITER}."
  fi

  FAIL_SNIPPET="$(tail -n 500 "${TEST_LOG}" || true)"
  STAGED_DIFF="$(git diff --staged --no-color || true)"
  WORKING_DIFF="$(git diff --no-color || true)"
  DIFF_TO_SEND="${STAGED_DIFF:-${WORKING_DIFF}}"
  if [ -z "${DIFF_TO_SEND}" ]; then
    echo "No diff found to repair; aborting AI loop."
    break
  fi

  printf "%s\n\n%s\n\n%s\n" "TASK: Create a single unified git patch (unified diff starting with 'diff --git') that updates the repository source code so that all 'go test ./...' pass, and all 'go vet' and 'gofmt' issues are resolved. Only modify Go source files and module files as necessary. Do not include extra commentary. Output exactly one unified diff and nothing else. Wrap the unified diff starting with 'diff --git' (no additional prefixes)." \
    "FAILING_TESTS_OUTPUT (excerpt):" "$FAIL_SNIPPET" > sendable-context.tmp
  printf "\n---BEGIN_DIFF---\n%s\n---END_DIFF---\n" "$DIFF_TO_SEND" >> sendable-context.tmp

  redact < sendable-context.tmp > sendable-context.redacted.tmp || true
  PROMPT_CONTENT="$(sed 's/\\/\\\\/g; s/"/\\"/g' sendable-context.redacted.tmp)"

  build_payload "$PROMPT_CONTENT" | tee "${REQUEST_FILE}"

  HTTP_RESPONSE=$(curl -sS -X POST "${API_URL}" \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    --data-binary @"${REQUEST_FILE}" -w "\n%{http_code}" || true)

  HTTP_BODY="$(printf "%s" "$HTTP_RESPONSE" | sed '$d')"
  HTTP_STATUS="$(printf "%s" "$HTTP_RESPONSE" | tail -n1)"
  printf "%s" "$HTTP_BODY" > "${RESPONSE_FILE}"
  echo "HTTP status: ${HTTP_STATUS}"

  redact < "${RESPONSE_FILE}" > "${RESPONSE_FILE}.redacted" || true

  AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // .result[0].content[0].text // empty' "${RESPONSE_FILE}" 2>/dev/null || true)"
  if [ -z "${AI_CONTENT}" ]; then
    AI_CONTENT="$(cat "${RESPONSE_FILE}")"
  fi

  printf "%s" "${AI_CONTENT}" > ai-response.raw.txt

  printf "%s\n" "${AI_CONTENT}" | sed -n '/^diff --git /,$p' > "${PATCH_FILE}" || true

  if [ ! -s "${PATCH_FILE}" ]; then
    echo "AI did not return a unified diff starting with 'diff --git'. Aborting AI loop." | tee -a "${TEST_LOG}"
    cat ai-response.raw.txt >> "${TEST_LOG}" || true
    break
  fi

  set +e
  git apply --index "${PATCH_FILE}" 2>apply.err
  APPLY_EXIT=$?
  set -e

  if [ ${APPLY_EXIT} -ne 0 ]; then
    echo "git apply failed; saving apply.err and aborting AI loop."
    cat apply.err >> "${TEST_LOG}" || true
    cat ai-response.raw.txt >> "${TEST_LOG}" || true
    break
  fi

  git add -A
  git commit -m "chore: ai automated refactor for dependency upgrades (iteration ${ITER})" || true

done

if [ -f "${PATCH_FILE}" ] && [ -s "${PATCH_FILE}" ]; then
  echo "Final AI patch saved to ${PATCH_FILE}."
else
  : > "${PATCH_FILE}" || true
fi

gofmt -l . > /dev/null 2>&1 || true
golangci-lint run ./... 2>&1 | tee -a "${LINTER_LOG}" || true
go vet ./... 2>&1 | tee -a "${TEST_LOG}" || true
go test ./... 2>&1 | tee -a "${TEST_LOG}" || true || true

gitleaks detect --report-path="${GITLEAKS_LOG}" || true

echo "Attempting to push changes to remote..."
set +e
git push --set-upstream origin "${BRANCH_NAME}" 2>&1 | tee push.log
PUSH_EXIT=${PIPESTATUS[0]}
set -e

if [ ${PUSH_EXIT} -ne 0 ]; then
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
    printf "%s\n" "$PR_RESPONSE" >> "${TEST_LOG}"
  fi
else
  set +e
  git checkout "${DEFAULT_BRANCH}"
  git pull origin "${DEFAULT_BRANCH}"
  git merge --ff-only "${BRANCH_NAME}" 2>&1 | tee -a push.log || true
  MERGE_EXIT=${PIPESTATUS[0]}
  set -e
  if [ ${MERGE_EXIT} -eq 0 ]; then
    git push origin "${DEFAULT_BRANCH}" || true
  fi
fi

redact < "${REQUEST_FILE}" > "${REQUEST_FILE}.redacted" || true
redact < "${RESPONSE_FILE}" > "${RESPONSE_FILE}.redacted" || true

cp -f "${REQUEST_FILE}.redacted" ai-request.json || true
cp -f "${RESPONSE_FILE}.redacted" ai-response.json || true
cp -f "${PATCH_FILE}" ai.patch || true
cp -f "${TEST_LOG}" tests.log || true
cp -f "${LINTER_LOG}" linter.log || true
cp -f "${GITLEAKS_LOG}" gitleaks.log || true

echo "ai_refactor.sh completed."
