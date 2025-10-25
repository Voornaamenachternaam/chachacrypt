#!/usr/bin/env bash
# File: .github/scripts/ai_refactor.sh
set -euo pipefail

# Usage: ./ai_refactor.sh --artifacts <path>
ARTIFACTS_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [ -z "$ARTIFACTS_DIR" ]; then
  echo "Usage: $0 --artifacts <path-to-artifacts>"
  exit 1
fi

WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
ART_DIR="${WORKDIR}/${ARTIFACTS_DIR}"
mkdir -p "${ART_DIR}"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"

TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
PATCH_BEFORE="${ART_DIR}/ai-diff-before.patch"
PATCH_AFTER="${ART_DIR}/ai-diff-after.patch"
DIAG="${ART_DIR}/ai-diagnostics.txt"
RAW_AI_RESPONSE="${ART_DIR}/ai-raw-response.json"

# Ensure jq is available for JSON parsing
if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y jq >/dev/null 2>&1 || true
  fi
fi

cd "${WORKDIR}"
git config --global --add safe.directory "${WORKDIR}" || true
git remote remove origin-auth 2>/dev/null || true
git remote add origin-auth "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" 2>/dev/null || true
git fetch --all --tags --prune || true
git fetch origin main || true

# Save before-diff
git diff -- "${TARGET_FILES[@]}" > "${PATCH_BEFORE}" 2>/dev/null || true

# Build diagnostics
{
  echo "=== AI diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
  echo "Repository: ${GITHUB_REPOSITORY}"
  echo
  echo "=== Target files presence ==="
  for f in "${TARGET_FILES[@]}"; do
    if [ -f "${WORKDIR}/$f" ]; then
      echo "FOUND: ${f}"
    else
      echo "MISSING: ${f}"
    fi
  done
} >> "${DIAG}" 2>&1

# Attempt safe auto-fixes (gofmt, goimports, golangci-lint, go mod tidy)
{
  echo >> "${DIAG}"
  echo "=== Auto-format and lint fixes ==="
  gofmt -s -w "${TARGET_FILES[@]}" >> "${ART_DIR}/auto-fix.log" 2>&1 || true
  goimports -w "${TARGET_FILES[@]}" >> "${ART_DIR}/auto-fix.log" 2>&1 || true
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=10m ./... >> "${ART_DIR}/auto-fix.log" 2>&1 || true
  fi
  go mod tidy >> "${ART_DIR}/auto-fix.log" 2>&1 || true
} || true

# If auto-fix changed any target file, commit & push branch
CHANGED_FILES=$(git status --porcelain | awk '{print $2}' || true)
if [ -n "${CHANGED_FILES}" ]; then
  for tf in "${TARGET_FILES[@]}"; do
    if echo "${CHANGED_FILES}" | grep -Fqx "$tf"; then
      TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
      BRANCH="ai/auto-fix-${TIMESTAMP}"
      git checkout -b "${BRANCH}"
      git add "${TARGET_FILES[@]}" 2>/dev/null || true
      git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix) for ${TARGET_FILES[*]}" || true
      git push --set-upstream origin-auth "${BRANCH}" || true
      echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
      git diff origin/main.."${BRANCH}" > "${PATCH_AFTER}" 2>/dev/null || true
      cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
      exit 0
    fi
  done
fi

# Re-run golangci-lint (full run) to capture remaining issues
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --fast=false --out-format json ./... > "${ART_DIR}/golangci.runtime.json" 2> "${ART_DIR}/golangci.runtime.stderr" || true
fi

relevant=false
# Run build/test to find any remaining errors
set +e
go build ./... > "${ART_DIR}/go-build-output.txt" 2>&1; build_exit=$?
go test ./... > "${ART_DIR}/go-test-output.txt" 2>&1; test_exit=$?
set -e
echo "Build exit code: $build_exit, Test exit code: $test_exit" >> "${DIAG}"
if [ "$relevant" = false ]; then
  if [ $build_exit -ne 0 ] || [ $test_exit -ne 0 ]; then
    relevant=true
  fi
fi

# Determine whether lint issues affect target files
if [ -f "${ART_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  files_in_json=$(jq -r '.Issues[]?.Pos?.Filename // empty' "${ART_DIR}/golangci.runtime.json" | sort -u | tr '\n' ' ')
  for f in $files_in_json; do
    for tf in "${TARGET_FILES[@]}"; do
      if [[ "$f" == *"$tf" ]]; then
        relevant=true
        break 2
      fi
    done
  done
else
  if grep -E "chachacrypt.go|go.mod|go.sum" "${ART_DIR}/golangci.runtime.stderr" >/dev/null 2>&1; then
    relevant=true
  fi
fi

if [ "$relevant" = false ]; then
  echo "No relevant issues found; skipping AI fix." >> "${DIAG}"
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Build the AI prompt using only relevant snippets and outputs
PROMPT_TMP="$(mktemp)"
{
  echo "You are an expert Go maintainer. Produce a single unified git diff patch (git format) with all fixes and improvements, enclosed in triple backticks. Only modify the listed files (chachacrypt.go, go.mod, go.sum) as needed."
  echo
  echo "Goals:"
  echo "1) Fix all lint, build, and test issues affecting the listed files. Use modern Go practices and keep changes minimal and safe."
  echo "2) Do not alter program behavior beyond necessary fixes. Add safe improvements (e.g., error checks) if needed, but avoid unrelated large refactors."
  echo "3) If modifying go.mod, prefer minimal dependency bumps and update go.sum accordingly."
  echo
  echo "=== Relevant golangci-lint issues (extracted) ==="
  if [ -f "${ART_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
    jq -r '.Issues[]? | "\(.FromLinter) | \(.Pos.Filename):\(.Pos.Line) | \(.Text)"' "${ART_DIR}/golangci.runtime.json" | sed -n '1,200p'
  else
    sed -n '1,200p' "${ART_DIR}/golangci.runtime.stderr" || true
  fi
  echo
  echo "=== File snippets (context ±5 lines) ==="
  if [ -f "${ART_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
    jq -r '.Issues[]?.Pos?.Filename // empty' "${ART_DIR}/golangci.runtime.json" | sort -u | while read -r f; do
      [ -z "$f" ] && continue
      if [ -f "$f" ]; then
        echo "<<< FILE: $f >>>"
        jq -r --arg file "$f" '.Issues[]? | select(.Pos.Filename == $file) | .Pos.Line' "${ART_DIR}/golangci.runtime.json" \
          | sort -n | uniq | while read -r ln; do
            start=$((ln > 5 ? ln - 5 : 1))
            end=$((ln + 5))
            echo "---- snippet around line $ln ----"
            sed -n "${start},${end}p" "$f" || true
            echo
        done
        echo "<<< END FILE: $f >>>"
        echo
      else
        echo "File $f not present in repo; cannot show snippet."
      fi
    done
  fi
   echo
   echo "=== Build output ==="
   if [ -s "${ART_DIR}/go-build-output.txt" ]; then
     sed -n '1,200p' "${ART_DIR}/go-build-output.txt"
   else
     echo "(no build output or errors)"
   fi
   echo
   echo "=== Test output ==="
   if [ -s "${ART_DIR}/go-test-output.txt" ]; then
     sed -n '1,200p' "${ART_DIR}/go-test-output.txt"
   else
     echo "(no test output or errors)"
   fi
} > "$PROMPT_TMP"

# Call OpenRouter Chat Completions API
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="minimax/minimax-m2:free"
PAYLOAD=$( jq -n \
  --arg model "$MODEL" \
  --arg sys "You are a concise assistant to a Go engineer." \
  --arg usr "$(sed -n '1,20000p' "$PROMPT_TMP")" \
  '{
    model: $model,
    messages: [
      {role:"system", content:$sys},
      {role:"user", content:$usr}
    ],
    temperature: 0.0,
    max_tokens: 32768
  }' )

RESPONSE_TMP="$(mktemp)"
HTTP_CODE=$(curl -sS -X POST "$API_URL" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" -w "%{http_code}" -o "$RESPONSE_TMP")

# Save raw AI response
mkdir -p "${ART_DIR}"
cp "$RESPONSE_TMP" "${RAW_AI_RESPONSE}" || true

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "AI API call failed with HTTP $HTTP_CODE" >> "${DIAG}"
  cat "$RESPONSE_TMP" >> "${DIAG}" || true
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // empty' "$RESPONSE_TMP" 2>/dev/null || true)"
if [ -z "$AI_CONTENT" ]; then
  echo "AI returned empty content; saving response to diagnostics." >> "${DIAG}"
  cat "$RESPONSE_TMP" >> "${DIAG}" || true
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Extract patch from AI content (looking for triple-backtick fenced diff)
echo "$AI_CONTENT" > /tmp/ai_content.txt
PATCH_AFTER="$(mktemp)"
if grep -q '```diff' /tmp/ai_content.txt; then
  sed -n '/```diff/,/```/p' /tmp/ai_content.txt | sed '1d;$d' > "${PATCH_AFTER}"
elif grep -q '```' /tmp/ai_content.txt; then
  sed -n '/```/,/```/p' /tmp/ai_content.txt | sed '1d;$d' > "${PATCH_AFTER}"
else
  echo "Failed to extract patch from AI response" >> "${DIAG}"
  echo "AI raw content:" >> "${DIAG}"
  echo "$AI_CONTENT" >> "${DIAG}"
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate that patch applies cleanly
if git apply --check "${PATCH_AFTER}" 2> /tmp/ai_patch_errors.txt; then
  git apply "${PATCH_AFTER}"
else
  echo "AI patch failed git apply --check" >> "${DIAG}"
  echo "Patch errors:" >> "${DIAG}"
  cat /tmp/ai_patch_errors.txt >> "${DIAG}" || true
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate the patched code: build, test, lint
VALID_OK=true
{
  set +e
  go mod tidy >> "${ART_DIR}/ai-validate.log" 2>&1 || true
  go build ./... >> "${ART_DIR}/ai-validate.log" 2>&1
  if [ $? -ne 0 ]; then VALID_OK=false; fi
  go test ./... >> "${ART_DIR}/ai-validate.log" 2>&1
  if [ $? -ne 0 ]; then VALID_OK=false; fi
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --timeout=10m --fast=false --out-format json ./... > "${ART_DIR}/golangci.postpatch.json" 2>> "${ART_DIR}/golangci.postpatch.stderr" || true
  fi
  set -e
} || true

if [ "$VALID_OK" = false ]; then
  echo "Validation (build/test) failed after applying AI patch. Reverting." >> "${DIAG}"
  git checkout -f main
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  exit 0
fi

# Determine which target files changed
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "${CHANGED_NOW}" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=( "$tf" )
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch applied but did not change target files. Exiting." >> "${DIAG}"
  git diff > "${ART_DIR}/ai-diff-after.patch" 2>/dev/null || true
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Commit & push AI fixes
TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/ai-fix-${TIMESTAMP}"
git checkout -b "${BRANCH}"
for f in "${CHANGED_TARGETS[@]}"; do
  git add "$f" || true
done
git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true
git push --set-upstream origin-auth "${BRANCH}" || true

git diff origin/main.."${BRANCH}" > "${ART_DIR}/ai-diff-after.patch" 2>/dev/null || true
cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true

echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
exit 0
