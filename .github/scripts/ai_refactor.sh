# File: .github/scripts/ai_refactor.sh
#!/usr/bin/env bash
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

# Ensure required env vars exist (GH2_TOKEN optional but recommended)
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"

# Tools
command -v git >/dev/null 2>&1 || { echo "git required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl required"; exit 1; }

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found; attempting apt-get install jq (best-effort)"
  sudo apt-get update -y >/dev/null 2>&1 || true
  sudo apt-get install -y jq >/dev/null 2>&1 || true
fi

TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
DIAG="${ART_DIR}/ai-diagnostics.txt"
PATCH_BEFORE="${ART_DIR}/ai-diff-before.patch"
PATCH_AFTER="${ART_DIR}/ai-diff-after.patch"

# Helper to write job output (works with GITHUB_OUTPUT)
set_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "pr_branch=$1" >> "${GITHUB_OUTPUT}"
  else
    echo "pr_branch=$1"
  fi
}

# Normalize git config and fetch all
git config --global --add safe.directory "${WORKDIR}" || true
git remote remove origin-auth 2>/dev/null || true
# Keep original origin; set an auth remote for pushing
git remote add origin-auth "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" 2>/dev/null || true

# Ensure we have origin refs
git fetch --no-tags --prune --depth=1 origin || true
git fetch --no-tags --prune --depth=1 origin main || true
git fetch --no-tags --prune origin || true

# Save before-diff
git diff -- "${TARGET_FILES[@]}" > "${PATCH_BEFORE}" || true

# Create diagnostics file
{
  echo "=== AI diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
  echo "Repository: ${GITHUB_REPOSITORY}"
  echo
  echo "=== Files present ==="
  for f in "${TARGET_FILES[@]}"; do
    echo "FILE: $f -> $( [ -f "${WORKDIR}/${f}" ] && echo "present" || echo "missing" )"
  done
  echo
  echo "=== golangci stdout/stderr (combined) ==="
  for ff in "${ART_DIR}/golangci.stdout" "${ART_DIR}/golangci.stderr" "${ART_DIR}/golangci.json"; do
    if [ -f "$ff" ]; then
      echo "---- $ff ----"
      sed -n '1,400p' "$ff" || true
      echo
    fi
  done
  echo "=== staticcheck ==="
  if [ -f "${ART_DIR}/staticcheck.txt" ]; then sed -n '1,400p' "${ART_DIR}/staticcheck.txt"; fi
  echo
  echo "=== build log ==="
  if [ -f "${ART_DIR}/ai-build.log" ]; then sed -n '1,400p' "${ART_DIR}/ai-build.log"; fi
} > "${DIAG}"

# Attempt automated safe fixes first (gofmt + golangci-lint --fix + go mod tidy)
(
  set -euo pipefail
  cd "${WORKDIR}"
  if command -v gofmt >/dev/null 2>&1; then
    gofmt -w .
  fi
  if command -v golangci-lint >/dev/null 2>&1; then
    # attempt auto-fixes; non-fatal
    golangci-lint run --fix --timeout=10m ./... >> "${ART_DIR}/auto-fix.log" 2>&1 || true
  fi
  go mod tidy >> "${ART_DIR}/auto-fix.log" 2>&1 || true
) || true

# If auto-fix changed any target file, create branch and push (prefers automated fixes)
CHANGED_FILES=$(git status --porcelain | awk '{print $2}' || true)
BRANCH=""
for tf in "${TARGET_FILES[@]}"; do
  if echo "${CHANGED_FILES}" | grep -Fqx "$tf"; then
    # Create branch and commit only the target files
    TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
    BRANCH="ai/auto-fix-${TIMESTAMP}"
    git checkout -b "${BRANCH}"
    git add ${TARGET_FILES[@]} 2>/dev/null || true
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix) for ${TARGET_FILES[*]}" || true
    git push --set-upstream origin-auth "${BRANCH}" || true
    echo "Automated fixes applied and pushed to branch ${BRANCH}" >> "${DIAG}"
    # Save diffs
    git diff origin/main.."${BRANCH}" > "${PATCH_AFTER}" || true
    set_output "${BRANCH}"
    exit 0
  fi
done

# Re-run full linters locally to capture latest state
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --fast=false --out-format json ./... > "${ART_DIR}/golangci.runtime.json" 2> "${ART_DIR}/golangci.runtime.stderr" || true
fi

# Determine if remaining diagnostics reference target files
relevant=false
if [ -f "${ART_DIR}/golangci.runtime.json" ]; then
  if command -v jq >/dev/null 2>&1; then
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
    # fallback grep
    if grep -E "chachacrypt.go|go.mod|go.sum" "${ART_DIR}/golangci.runtime.json" >/dev/null 2>&1; then
      relevant=true
    fi
  fi
fi

# If not relevant, no AI action needed
if [ "$relevant" = false ]; then
  echo "No issues affecting target files detected after auto-fix. Exiting." >> "${DIAG}"
  set_output ""
  exit 0
fi

# Build AI prompt: include current target files and diagnostics
PROMPT_FILE="$(mktemp)"
{
  echo "You are an expert Go maintainer. Produce a minimal safe unified diff patch (git-style) that modifies only these files if strictly necessary: chachacrypt.go, go.mod, go.sum."
  echo "Goals:"
  echo "1) Fix the remaining linter/build/test issues visible in diagnostics while preserving semantics."
  echo "2) Prefer minimal edits; prefer type inference removal, check Close() errors, remove redundant casts, fix errcheck, and small adjustments to compile with the latest stable Go."
  echo "3) If you update go.mod's 'go' directive or dependencies, prefer minor/patch bumps and update go.sum accordingly."
  echo "4) Only return a single unified diff patch (starting with 'diff --git a/... b/...'). Do not add explanatory text. If no safe patch can be produced, return an empty response."
  echo
  echo "=== Current files (truncated) ==="
  for tf in "${TARGET_FILES[@]}"; do
    if [ -f "${WORKDIR}/${tf}" ]; then
      echo "<<< BEGIN FILE: ${tf} >>>"
      sed -n '1,2000p' "${WORKDIR}/${tf}"
      echo "<<< END FILE: ${tf} >>>"
      echo
    else
      echo "<<< BEGIN FILE: ${tf} >>>"
      echo "<file missing>"
      echo "<<< END FILE: ${tf} >>>"
      echo
    fi
  done
  echo
  echo "=== Diagnostics (truncated) ==="
  sed -n '1,2000p' "${DIAG}" || true
  if [ -f "${ART_DIR}/golangci.runtime.json" ]; then
    echo
    echo "=== GolangCI JSON (issues list) ==="
    if command -v jq >/dev/null 2>&1; then
      jq -r '.Issues[]? | "\(.Pos? // "") | \(.FromLinter // ""): \(.Text // "")"' "${ART_DIR}/golangci.runtime.json" | sed -n '1,200p'
    else
      sed -n '1,200p' "${ART_DIR}/golangci.runtime.json" || true
    fi
  fi
} > "${PROMPT_FILE}"

# Call OpenRouter API (Chat Completions)
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="tngtech/deepseek-r1t2-chimera:free"

PAYLOAD=$( jq -n --arg model "$MODEL" --arg sys "You are a careful, conservative Go engineer." --arg usr "$(sed -n '1,20000p' "$PROMPT_FILE")" '{
  model: $model,
  messages: [
    {role:"system", content:$sys},
    {role:"user", content:$usr}
  ],
  temperature: 0.0,
  max_tokens: 32768
}' )

RESPONSE="$(mktemp)"
HTTP_CODE=$(curl -sS -X POST "$API_URL" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" -w "%{http_code}" -o "$RESPONSE" )

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "AI API call failed with HTTP $HTTP_CODE" >> "${DIAG}"
  cat "$RESPONSE" >> "${DIAG}"
  set_output ""
  exit 0
fi

AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // empty' "$RESPONSE" 2>/dev/null || true)
if [ -z "$AI_CONTENT" ]; then
  echo "AI returned empty content; saving response to diagnostics." >> "${DIAG}"
  cat "$RESPONSE" >> "${DIAG}"
  set_output ""
  exit 0
fi

# Extract unified diff from AI_CONTENT
echo "$AI_CONTENT" > /tmp/ai_content.txt
# Prefer fenced code extraction
awk 'BEGIN{p=0} /^```/{ if(p==0){p=1; next} else {p=0; next} } p{print}' /tmp/ai_content.txt > "${PATCH_AFTER}" || true
if [ ! -s "${PATCH_AFTER}" ]; then
  awk '/^diff --git /{p=1} p{print}' /tmp/ai_content.txt > "${PATCH_AFTER}" || true
fi

if [ ! -s "${PATCH_AFTER}" ]; then
  echo "Failed to extract patch from AI response" >> "${DIAG}"
  echo "$AI_CONTENT" >> "${DIAG}"
  set_output ""
  exit 0
fi

# Validate patch
if git apply --check "${PATCH_AFTER}" 2> /tmp/ai_patch_errors.txt; then
  git apply "${PATCH_AFTER}"
else
  echo "AI patch failed git apply --check" >> "${DIAG}"
  cat /tmp/ai_patch_errors.txt >> "${DIAG}"
  set_output ""
  exit 0
fi

# Determine changed target files
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "${CHANGED_NOW}" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=( "$tf" )
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch applied but did not change target files. Saving diffs and exiting." >> "${DIAG}"
  git diff > "${PATCH_AFTER}" || true
  set_output ""
  exit 0
fi

# Create branch, commit only allowed files, push using auth remote
TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/ai-fix-${TIMESTAMP}"
git checkout -b "${BRANCH}"
for f in "${CHANGED_TARGETS[@]}"; do
  git add "$f" || true
done
git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true
git push --set-upstream origin-auth "${BRANCH}" || true

# Save diffs
git diff origin/main.."${BRANCH}" > "${PATCH_AFTER}" || true
echo "AI patch applied and pushed to branch ${BRANCH}" >> "${DIAG}"

# Upload diagnostics and patches into ART_DIR for workflow to upload as artifacts
cp "${DIAG}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true
cp "${PATCH_BEFORE}" "${ART_DIR}/ai-diff-before.patch" 2>/dev/null || true
cp "${PATCH_AFTER}" "${ART_DIR}/ai-diff-after.patch" 2>/dev/null || true

# Set pr_branch output
set_output "${BRANCH}"

# Cleanup temp files
rm -f "${PROMPT_FILE}" "${RESPONSE}" /tmp/ai_content.txt /tmp/ai_patch_errors.txt || true

exit 0
