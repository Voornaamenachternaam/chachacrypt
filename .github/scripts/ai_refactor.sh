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
DIAG="${ART_DIR}/ai-diagnostics.txt"
PATCH_BEFORE="${ART_DIR}/ai-diff-before.patch"
PATCH_AFTER="${ART_DIR}/ai-diff-after.patch"
RAW_AI_RESPONSE="${ART_DIR}/ai-raw-response.json"

# Ensure tools
command -v git >/dev/null 2>&1 || { echo "git required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl required"; exit 1; }
if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y jq >/dev/null 2>&1 || true
  fi
fi

cd "${WORKDIR}"

# Normalize git & fetch full history
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
    if [ -f "${WORKDIR}/${f}" ]; then
      echo "FOUND: ${f}"
    else
      echo "MISSING: ${f}"
    fi
  done
  echo
  echo "=== Artifacts samples ==="
  for sample in "${ART_DIR}"/*; do
    [ -f "$sample" ] || continue
    echo "---- $sample ----"
    sed -n '1,200p' "$sample" || true
    echo
  done
} > "${DIAG}"

# Conservative auto-fixes (formatting + golangci-lint --fix if available)
{
  set -euo pipefail
  if command -v gofmt >/dev/null 2>&1; then
    gofmt -w .
  fi
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

# Re-run golangci-lint to capture runtime issues
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --fast=false --out-format json ./... > "${ART_DIR}/golangci.runtime.json" 2> "${ART_DIR}/golangci.runtime.stderr" || true
fi

# Determine whether issues affect target files
relevant=false
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
  echo "No remaining issues affecting target files." >> "${DIAG}"
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Build focused prompt: include only relevant issue locations and file snippets (context +/- 5 lines)
PROMPT_TMP="$(mktemp)"
{
  echo "You are an expert, conservative Go maintainer. Produce a single unified git diff patch (git format) and nothing else, enclosed in triple backticks. Modify only these files if strictly necessary: chachacrypt.go, go.mod, go.sum."
  echo
  echo "Goals:"
  echo "1) Fix exact linter/build issues affecting the listed files. Keep changes minimal and safe."
  echo "2) Do not change program semantics beyond necessary fixes. If uncertain, prefer to add error checks or small safe edits, not large refactors."
  echo "3) If modifying go.mod, prefer minimal dependency bumps and update go.sum accordingly."
  echo
  echo "=== Relevant golangci-lint issues (extracted) ==="
  if [ -f "${ART_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
    jq -r '.Issues[]? | "\(.FromLinter) | \(.Pos.Filename):\(.Pos.Line):\(.Pos.Column) | \(.Text)"' "${ART_DIR}/golangci.runtime.json" | sed -n '1,200p'
  else
    sed -n '1,200p' "${ART_DIR}/golangci.runtime.stderr" || true
  fi
  echo
  echo "=== File snippets (context +/-5 lines) ==="
  if [ -f "${ART_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
    jq -r '.Issues[]?.Pos?.Filename // empty' "${ART_DIR}/golangci.runtime.json" | sort -u | while read -r f; do
      [ -z "$f" ] && continue
      if [ -f "$f" ]; then
        echo "<<< FILE: $f >>>"
        # for each issue in this file, show snippets
        jq -r --arg file "$f" '.Issues[]? | select(.Pos.Filename == $file) | .Pos.Line' "${ART_DIR}/golangci.runtime.json" | sort -n | uniq | while read -r ln; do
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
} > "$PROMPT_TMP"

# Call OpenRouter Chat Completions
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="tngtech/deepseek-r1t2-chimera:free"

PAYLOAD=$( jq -n --arg model "$MODEL" --arg sys "You are a careful, conservative Go engineer." --arg usr "$(sed -n '1,20000p' "$PROMPT_TMP")" '{
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
  -d "$PAYLOAD" -w "%{http_code}" -o "$RESPONSE_TMP" )

# Save raw response for debugging
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

# Extract patch from AI content (prefer fenced triple backticks)
echo "$AI_CONTENT" > /tmp/ai_content.txt
awk 'BEGIN{p=0} /^```/{ if(p==0){p=1; next} else {p=0; next} } p{print}' /tmp/ai_content.txt > "${PATCH_AFTER}" || true
if [ ! -s "${PATCH_AFTER}" ]; then
  awk '/^diff --git /{p=1} p{print}' /tmp/ai_content.txt > "${PATCH_AFTER}" || true
fi

if [ ! -s "${PATCH_AFTER}" ]; then
  echo "Failed to extract patch from AI response" >> "${DIAG}"
  echo "AI raw content:" >> "${DIAG}"
  echo "$AI_CONTENT" >> "${DIAG}"
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate patch applies cleanly
if git apply --check "${PATCH_AFTER}" 2> /tmp/ai_patch_errors.txt; then
  git apply "${PATCH_AFTER}"
else
  echo "AI patch failed git apply --check" >> "${DIAG}"
  cat /tmp/ai_patch_errors.txt >> "${DIAG}" || true
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Run validation: go build, go test, golangci-lint run
VALID_OK=true
{
  set +e
  go mod tidy >> "${ART_DIR}/ai-validate.log" 2>&1 || true
  go build ./... >> "${ART_DIR}/ai-validate.log" 2>&1
  if [ $? -ne 0 ]; then VALID_OK=false; fi
  go test ./... >> "${ART_DIR}/ai-validate.log" 2>&1
  if [ $? -ne 0 ]; then VALID_OK=false; fi
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --timeout=10m --fast=false --out-format json ./... > "${ART_DIR}/golangci.postpatch.json" 2> "${ART_DIR}/golangci.postpatch.stderr" || true
  fi
  set -e
} || true

if [ "$VALID_OK" != true ]; then
  echo "Validation (build/test) failed after applying AI patch. Reverting." >> "${DIAG}"
  git reset --hard HEAD --quiet || true
  git clean -fd || true
  cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Determine changed allowed files
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
