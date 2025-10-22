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

# Ensure required environment variables
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
DIAG_FILE="${ART_DIR}/ai-diagnostics.txt"
mkdir -p "${ART_DIR}"

safe_cat() {
  if [ -f "$1" ]; then cat "$1"; fi
}

# Create diagnostics
{
  echo "=== AI diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
  echo "Repository: ${GITHUB_REPOSITORY}"
  echo
  echo "=== golangci stdout ==="
  safe_cat "${ART_DIR}/golangci.stdout" || true
  echo
  echo "=== golangci stderr ==="
  safe_cat "${ART_DIR}/golangci.stderr" || true
  echo
  echo "=== golangci json (truncated) ==="
  if [ -f "${ART_DIR}/golangci.json" ]; then
    jq -r '.Issues[]? | {pos: .Pos, linter: .FromLinter, text: .Text}' "${ART_DIR}/golangci.json" | sed -n '1,200p' || true
  fi
  echo
  echo "=== staticcheck ==="
  safe_cat "${ART_DIR}/staticcheck.txt" || true
  echo
  echo "=== build log (truncated) ==="
  safe_cat "${ART_DIR}/ai-build.log" | sed -n '1,200p' || true
} > "${DIAG_FILE}"

# Determine relevance: if issues reference target files or build logs mention module/go problems
relevant=false
if [ -f "${ART_DIR}/golangci.json" ]; then
  mapfile -t files_in_json < <(jq -r '.Issues[]?.Pos?.Filename // empty' "${ART_DIR}/golangci.json" | sort -u)
  for f in "${files_in_json[@]}"; do
    for tf in "${TARGET_FILES[@]}"; do
      if [[ "$f" == *"$tf" ]]; then
        relevant=true
        break 2
      fi
    done
  done
fi

if grep -Ei "cannot find module|module|go [0-9]+\." "${ART_DIR}/ai-build.log" >/dev/null 2>&1; then
  relevant=true
fi

# If not relevant, exit with empty pr_branch output
if [ "$relevant" = false ]; then
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=" >> "${GITHUB_OUTPUT}"; fi
  exit 0
fi

# Prepare prompt context
PROMPT_FILE="$(mktemp)"
{
  echo "You are an expert Go maintainer. Produce a minimal, safe unified diff patch (git-format) that modifies only the following files if needed: chachacrypt.go, go.mod, go.sum."
  echo "Goals:"
  echo "1) Fix lint/build/test issues present in diagnostics while preserving behavior."
  echo "2) Update go directive and dependencies only when necessary; prefer minor/patch bumps."
  echo "3) If Go version update is required, ensure code compiles and necessary edits are included."
  echo
  echo "=== Current files ==="
  for tf in "${TARGET_FILES[@]}"; do
    if [ -f "${WORKDIR}/${tf}" ]; then
      echo "<<< BEGIN FILE: ${tf} >>>"
      sed -n '1,16000p' "${WORKDIR}/${tf}"
      echo "<<< END FILE: ${tf} >>>"
      echo
    fi
  done
  echo "=== Diagnostics (truncated) ==="
  sed -n '1,4000p' "${DIAG_FILE}" 2>/dev/null || true
  echo
  echo "Instructions: Return only a single unified diff patch (git-style, starting with 'diff --git a/... b/...') inside a code block or plain text. If no safe patch can be created, return an empty response."
} > "${PROMPT_FILE}"

# Call OpenRouter Chat Completions
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="tngtech/deepseek-r1t2-chimera:free"

PAYLOAD=$( jq -n --arg model "$MODEL" --arg sys "You are a helpful, careful Go engineer." --arg usr "$(sed -n '1,20000p' "$PROMPT_FILE")" '{
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
  -d "$PAYLOAD" -w "%{http_code}" -o "$RESPONSE")

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "AI API returned HTTP $HTTP_CODE" >> "${DIAG_FILE}"
  cat "$RESPONSE" >> "${DIAG_FILE}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=" >> "${GITHUB_OUTPUT}"; fi
  exit 0
fi

AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // empty' "$RESPONSE" 2>/dev/null || true)
if [ -z "$AI_CONTENT" ]; then
  echo "AI returned empty content; saving response to diagnostics." >> "${DIAG_FILE}"
  cat "$RESPONSE" >> "${DIAG_FILE}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=" >> "${GITHUB_OUTPUT}"; fi
  exit 0
fi

# Extract unified diff
PATCH_FILE="${ART_DIR}/ai-diff-after.patch"
echo "$AI_CONTENT" > /tmp/ai_content.txt
awk 'BEGIN{p=0} /^```/{ if(p==0){p=1; next} else {p=0; next} } p{print }' /tmp/ai_content.txt > "${PATCH_FILE}" || true
if [ ! -s "${PATCH_FILE}" ]; then
  awk '/^diff --git /{p=1} p{print}' /tmp/ai_content.txt > "${PATCH_FILE}" || true
fi

if [ ! -s "${PATCH_FILE}" ]; then
  echo "Failed to extract patch from AI response." >> "${DIAG_FILE}"
  echo "$AI_CONTENT" >> "${DIAG_FILE}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=" >> "${GITHUB_OUTPUT}"; fi
  exit 0
fi

# Save before diff
git diff -- "${TARGET_FILES[@]}" > "${ART_DIR}/ai-diff-before.patch" || true

# Validate and apply patch
if git apply --check "${PATCH_FILE}" 2> /tmp/ai_patch_errors.txt; then
  git apply "${PATCH_FILE}"
else
  echo "Patch failed git apply --check" >> "${DIAG_FILE}"
  cat /tmp/ai_patch_errors.txt >> "${DIAG_FILE}"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=" >> "${GITHUB_OUTPUT}"; fi
  exit 0
fi

# Determine changed target files
CHANGED=""
for f in "${TARGET_FILES[@]}"; do
  if git status --porcelain | awk '{print $2}' | grep -Fxq "$f" >/dev/null 2>&1; then
    CHANGED="${CHANGED} ${f}"
  fi
done

if [ -z "${CHANGED}" ]; then
  git diff > "${ART_DIR}/ai-diff-after.patch" || true
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=" >> "${GITHUB_OUTPUT}"; fi
  exit 0
fi

# Commit on new branch and push
TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/dep-updates-${TIMESTAMP}"
git checkout -b "${BRANCH}"

for f in ${TARGET_FILES[@]}; do
  if [ -f "$f" ]; then
    git add "$f" || true
  fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED}" || true

REMOTE_URL="https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
git push --set-upstream "${REMOTE_URL}" "${BRANCH}"

# Save after diff
git diff origin/main.."${BRANCH}" > "${ART_DIR}/ai-diff-after.patch" || true

# Expose the branch for the workflow to create a PR
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT}"
else
  echo "pr_branch=${BRANCH}"
fi

# Save diagnostics
cp "${DIAG_FILE}" "${ART_DIR}/ai-diagnostics.txt" 2>/dev/null || true

# Cleanup
rm -f /tmp/ai_content.txt "$RESPONSE" /tmp/ai_patch_errors.txt || true

exit 0
