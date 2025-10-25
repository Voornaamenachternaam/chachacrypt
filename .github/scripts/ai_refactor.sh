#!/usr/bin/env bash
# Minimal AI refactor script (OpenRouter) — concise, safe, pushes only allowed files
set -euo pipefail

ARTIFACTS_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done
if [ -z "$ARTIFACTS_DIR" ]; then
  echo "Usage: $0 --artifacts <path>"
  exit 1
fi

WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
ART_DIR="${WORKDIR}/${ARTIFACTS_DIR}"
mkdir -p "${ART_DIR}"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

cd "${WORKDIR}"
git config --global --add safe.directory "${WORKDIR}" || true
# Ensure origin uses GH2_TOKEN so pushes are on origin for create-pull-request to find
git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" || true
git fetch origin --prune --tags || true

TARGETS=(chachacrypt.go go.mod go.sum)

# Save before patch
git diff -- "${TARGETS[@]}" > "${ART_DIR}/ai-diff-before.patch" 2>/dev/null || true

# Try safe automatic fixes
gofmt -s -w . || true
go install golang.org/x/tools/cmd/goimports@latest >/dev/null 2>&1 || true
goimports -w . || true
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --fix --timeout=10m ./... > "${ART_DIR}/golangci.fix.out" 2>&1 || true
fi
go mod tidy > "${ART_DIR}/go-mod-tidy.out" 2>&1 || true

# If safe fixes touched targets, commit & push
if git status --porcelain | awk '{print $2}' | grep -F -q -x -e "${TARGETS[0]}" -e "${TARGETS[1]}" -e "${TARGETS[2]}" ; then
  TS=$(date -u +%Y%m%d%H%M%S)
  BR="ai/auto-fix-${TS}"
  git checkout -b "${BR}"
  for f in "${TARGETS[@]}"; do
    [ -f "$f" ] && git add -- "$f" || true
  done
  git commit -m "[create-pull-request] automated safe fixes" || true
  git push --set-upstream origin "${BR}" || true
  echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
  exit 0
fi

# Collect diagnostics
golangci-lint run --timeout=10m --out-format json ./... > "${ART_DIR}/golangci.json" 2> "${ART_DIR}/golangci.stderr" || true
go build ./... > "${ART_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ART_DIR}/go-test-output.txt" 2>&1 || true

# If nothing to fix, exit
if [ ! -s "${ART_DIR}/golangci.json" ] && ! grep -q . "${ART_DIR}/go-build-output.txt" && ! grep -q . "${ART_DIR}/go-test-output.txt"; then
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Build a compact prompt
PROMPT="$(cat <<'PROMPT'
You are an expert Go maintainer. Produce a single unified git diff (unified patch) enclosed in triple backticks that fixes the lint/build/test issues below.
Only modify chachacrypt.go, go.mod, and go.sum if necessary. Keep changes minimal and safe. If you update go.mod, keep version bumps minimal.
Include only the fenced patch in your reply.
=== LINT ===
PROMPT
)"
PROMPT="${PROMPT}\n$(sed -n '1,200p' "${ART_DIR}/golangci.stderr" 2>/dev/null || true)"
PROMPT="${PROMPT}\n\n=== BUILD ===\n$(sed -n '1,200p' "${ART_DIR}/go-build-output.txt" 2>/dev/null || true)"
PROMPT="${PROMPT}\n\n=== TEST ===\n$(sed -n '1,200p' "${ART_DIR}/go-test-output.txt" 2>/dev/null || true)"
PROMPT="${PROMPT}\n\nPlease produce only the patch."

# Call OpenRouter (Chat Completions)
API="https://api.openrouter.ai/v1/chat/completions"
MODEL="minimax/minimax-m2:free"
PAYLOAD=$(jq -n --arg m "$MODEL" --arg sys "You are a precise code patch generator." --arg usr "$PROMPT" \
  '{model:$m, messages:[{role:"system",content:$sys},{role:"user",content:$usr}], temperature:0.0, max_tokens:32768}')

RESP_TMP=$(mktemp)
HTTP=$(curl -sS -X POST "$API" -H "Authorization: Bearer ${OPENROUTER_API_KEY}" -H "Content-Type: application/json" -d "$PAYLOAD" -w "%{http_code}" -o "$RESP_TMP")

if [ "$HTTP" -lt 200 ] || [ "$HTTP" -ge 300 ]; then
  echo "OpenRouter HTTP $HTTP" > "${ART_DIR}/ai-raw-response.json" || true
  cat "$RESP_TMP" >> "${ART_DIR}/ai-raw-response.json" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

AI_TEXT=$(jq -r '.choices[0].message.content // .choices[0].text // ""' "$RESP_TMP" 2>/dev/null || true)
echo "$AI_TEXT" > "${ART_DIR}/ai-response.txt"

# Extract the first fenced block as patch
PATCH_TMP=$(mktemp)
if echo "$AI_TEXT" | grep -q '```'; then
  echo "$AI_TEXT" | sed -n '/```/,/```/p' | sed '1d;$d' > "$PATCH_TMP" || true
else
  echo "No fenced patch" > "${ART_DIR}/ai-diagnostics.txt"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate and apply
if ! git apply --check "$PATCH_TMP" > /tmp/patch.check 2>&1; then
  cat /tmp/patch.check > "${ART_DIR}/ai-diagnostics.txt"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi
git apply "$PATCH_TMP"

# Validate build & tests
set +e
go mod tidy > "${ART_DIR}/ai-go-mod-tidy.txt" 2>&1 || true
go build ./... > "${ART_DIR}/ai-build.txt" 2>&1
bcode=$?
go test ./... > "${ART_DIR}/ai-test.txt" 2>&1
tcode=$?
set -e

if [ $bcode -ne 0 ] || [ $tcode -ne 0 ]; then
  git checkout -- . || true
  echo "Validation failed after AI patch" > "${ART_DIR}/ai-diagnostics.txt"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Commit & push only allowed files
TS=$(date -u +%Y%m%d%H%M%S)
BR="ai/ai-fix-${TS}"
git checkout -b "${BR}"
for f in "${TARGETS[@]}"; do
  [ -f "$f" ] && git add -- "$f" || true
done
git commit -m "[create-pull-request] AI fixes" || true
git push --set-upstream origin "${BR}" || true

echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
exit 0
