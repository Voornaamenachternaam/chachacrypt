#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Robust drop-in replacement: uses jq or python to safely build JSON payloads and parse responses.
# - Forces bash execution if needed
# - Self-heals by installing goimports if missing
# - Runs safe auto-fixes; if still failing, asks OpenRouter for a fenced git patch
# - Validates patch, commits only allowed files, pushes branch to origin, prints pr_branch via GITHUB_OUTPUT
set -euo pipefail

# Re-exec under bash if not running under bash (ensures arrays, [[, etc.)
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi

# ---------- args ----------
ARTIFACTS_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$ARTIFACTS_DIR" ]; then
  echo "Usage: $0 --artifacts <path-to-artifacts>" >&2
  exit 1
fi

# ---------- env & paths ----------
WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
ART_DIR="${WORKDIR}/${ARTIFACTS_DIR}"
mkdir -p "$ART_DIR"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set (repo secret)}"
: "${GH2_TOKEN:?GH2_TOKEN must be set (repo secret)}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

cd "$WORKDIR"

# Mark workspace safe for git
git config --global --add safe.directory "$WORKDIR" >/dev/null 2>&1 || true

# Ensure origin remote is authenticated with GH2_TOKEN to avoid ambiguous branch refs
git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" >/dev/null 2>&1 || true
git fetch origin --prune --tags >/dev/null 2>&1 || true

# ---------- constants ----------
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

DIAG="${ART_DIR}/ai-diagnostics.txt"
AI_RAW="${ART_DIR}/ai-raw-response.json"
AI_RESP="${ART_DIR}/ai-response.txt"
PATCH_BEFORE="${ART_DIR}/ai-diff-before.patch"
PATCH_AFTER="${ART_DIR}/ai-diff-after.patch"
VALIDATE_LOG="${ART_DIR}/ai-validate.log"
PROMPT_TMP="$(mktemp)"

# header
{
  echo "ai_refactor.sh diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY}"
  echo "workspace: ${WORKDIR}"
  echo
} > "$DIAG"

# save before-diff
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# ---------- helper tools: jq (preferred) or python fallback ----------
HAS_JQ=false
HAS_PY=false
if command -v jq >/dev/null 2>&1; then
  HAS_JQ=true
fi
if command -v python3 >/dev/null 2>&1; then
  HAS_PY=true
elif command -v python >/dev/null 2>&1; then
  HAS_PY=true
fi

# ---------- ensure go and goimports ----------
if ! command -v go >/dev/null 2>&1; then
  echo "go command not available; aborting." >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

GOBIN="${GOBIN:-$HOME/go/bin}"
mkdir -p "$GOBIN"
export GOBIN
case ":$PATH:" in
  *":$GOBIN:"*) ;;
  *) PATH="$GOBIN:$PATH" ;;
esac

if ! command -v goimports >/dev/null 2>&1; then
  echo "goimports missing; trying to install..." >> "$DIAG"
  if go install golang.org/x/tools/cmd/goimports@latest >/dev/null 2>&1; then
    echo "goimports installed" >> "$DIAG"
    PATH="$GOBIN:$PATH"
  else
    echo "goimports install failed; continuing" >> "$DIAG"
  fi
fi

if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "golangci-lint not found; some auto-fixes will be skipped" >> "$DIAG"
fi

# ---------- safe auto-fixes ----------
{
  echo "Running safe auto-fixes..." >> "$DIAG"
  gofmt -s -w . || true
  if command -v goimports >/dev/null 2>&1; then
    goimports -w . || true
  fi
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=10m ./... >> "${ART_DIR}/golangci-fix.log" 2>&1 || true
  fi
  go mod tidy >> "${ART_DIR}/go-mod-tidy.log" 2>&1 || true
} || true

# if safe fixes changed targets -> commit & push and exit
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
    BRANCH="ai/auto-fix-${TIMESTAMP}"
    git checkout -b "$BRANCH"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    for f in "${TARGET_FILES[@]}"; do
      [ -f "$f" ] && git add -- "$f" || true
    done
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    if git push --set-upstream origin "$BRANCH" >/dev/null 2>&1; then
      echo "Safe-fix branch pushed: $BRANCH" >> "$DIAG"
      git diff origin/main.."${BRANCH}" > "$PATCH_AFTER" 2>/dev/null || true
      cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
      echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
      exit 0
    else
      echo "Failed to push safe-fix branch $BRANCH" >> "$DIAG"
      cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
      echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
      exit 0
    fi
  fi
done

# ---------- collect diagnostics for AI ----------
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --out-format json ./... > "${ART_DIR}/golangci.runtime.json" 2> "${ART_DIR}/golangci.runtime.stderr" || true
fi

go build ./... > "${ART_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ART_DIR}/go-test-output.txt" 2>&1 || true

NEED_AI=false
if [ -s "${ART_DIR}/go-build-output.txt" ] || [ -s "${ART_DIR}/go-test-output.txt" ]; then
  NEED_AI=true
fi
if [ -f "${ART_DIR}/golangci.runtime.json" ] && [ "$HAS_JQ" = true ]; then
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ART_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|%s|%s' "${TARGET_FILES[0]}" "${TARGET_FILES[1]}" "${TARGET_FILES[2]}")" >/dev/null 2>&1; then
    NEED_AI=true
  fi
fi

if [ "$NEED_AI" = false ]; then
  echo "No AI-needed issues; exiting." >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------- create a safe prompt file (no embedded JSON building here) ----------
{
  echo "You are an expert Go maintainer. Produce a single unified git diff patch (enclosed in triple backticks) that fixes the lint/build/test issues below."
  echo "Modify only these files if necessary: ${TARGET_FILES[*]}. Keep changes minimal and safe."
  echo
  echo "=== LINT (truncated) ==="
  sed -n '1,200p' "${ART_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo
  echo "=== BUILD (truncated) ==="
  sed -n '1,200p' "${ART_DIR}/go-build-output.txt" 2>/dev/null || true
  echo
  echo "=== TEST (truncated) ==="
  sed -n '1,200p' "${ART_DIR}/go-test-output.txt" 2>/dev/null || true
  echo
  echo "=== FILES (first 200 lines) ==="
  for f in "${TARGET_FILES[@]}"; do
    if [ -f "$f" ]; then
      echo "----- FILE: $f -----"
      sed -n '1,200p' "$f" || true
      echo
    fi
  done
} > "$PROMPT_TMP"

# ---------- build JSON payload to file safely ----------
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="minimax/minimax-m2:free"
PAYLOAD_FILE="$(mktemp)"

if [ "$HAS_JQ" = true ]; then
  # Use jq to construct JSON safely
  jq -n --arg model "$MODEL" \
        --arg sys "You are an expert Go code patch generator. Provide exactly one fenced diff patch." \
        --arg usr "$(sed -n '1,20000p' "$PROMPT_TMP")" \
        '{
          model: $model,
          messages: [
            {role:"system", content:$sys},
            {role:"user", content:$usr}
          ],
          temperature: 0.0,
          max_tokens: 32768
        }' > "$PAYLOAD_FILE"
else
  # Use Python to create JSON safely (handles quotes/newlines robustly)
  if [ "$HAS_PY" = true ]; then
    python3 - <<PY > "$PAYLOAD_FILE" || python - <<PY > "$PAYLOAD_FILE"
import json,sys
MODEL = "$MODEL"
system = "You are an expert Go code patch generator. Provide exactly one fenced diff patch."
with open("$PROMPT_TMP","r", encoding="utf-8") as fh:
    user = fh.read()
payload = {
  "model": MODEL,
  "messages": [
    {"role":"system","content": system},
    {"role":"user","content": user}
  ],
  "temperature": 0.0,
  "max_tokens": 32768
}
json.dump(payload, sys.stdout, ensure_ascii=False)
PY
  else
    echo "Neither jq nor python available to safely build JSON payload; aborting." >> "$DIAG"
    cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
    echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
    exit 0
  fi
fi

# ---------- call OpenRouter ----------
RESPONSE_TMP="$(mktemp)"
HTTP_CODE=$(curl -sS -X POST "$API_URL" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @"$PAYLOAD_FILE" -w "%{http_code}" -o "$RESPONSE_TMP" )

cp "$RESPONSE_TMP" "$AI_RAW" || true

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "OpenRouter API returned HTTP $HTTP_CODE" >> "$DIAG"
  cat "$RESPONSE_TMP" >> "$DIAG" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------- extract AI content (jq preferred, python fallback) ----------
AI_CONTENT=""
if [ "$HAS_JQ" = true ]; then
  AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // empty' "$RESPONSE_TMP" 2>/dev/null || true)
else
  # use python to parse JSON safely if jq missing
  if [ "$HAS_PY" = true ]; then
    AI_CONTENT=$(python3 - <<PY 2>/dev/null || python - <<PY 2>/dev/null
import json,sys
try:
    obj=json.load(open("$RESPONSE_TMP", "r", encoding="utf-8"))
    # try chat completions shape
    out = ""
    if "choices" in obj and len(obj["choices"])>0:
        ch = obj["choices"][0]
        if isinstance(ch, dict):
            out = ch.get("message", {}).get("content") or ch.get("text") or ""
    print(out or "")
except Exception as e:
    sys.stderr.write("json parse error: "+str(e))
    print("", end="")
PY
  else
    AI_CONTENT=$(sed -n '1,20000p' "$RESPONSE_TMP")
  fi
fi

echo "$AI_CONTENT" > "$AI_RESP"

# ---------- extract first fenced block from AI_CONTENT robustly (python fallback) ----------
PATCH_TMP="$(mktemp)"
# Try to extract using awk/sed but if complex, use python
if echo "$AI_CONTENT" | grep -q '```'; then
  # Prefer python extraction for correctness
  if [ "$HAS_PY" = true ]; then
    python3 - <<PY > "$PATCH_TMP" 2>/dev/null || python - <<PY > "$PATCH_TMP" 2>/dev/null
import sys,re
s = sys.stdin.read()
# find first fenced block (```...```)
m = re.search(r'```(?:[^\n]*)\n(.*?)\n```', s, re.S)
if m:
    print(m.group(1))
else:
    # fallback: between first and second ```
    parts = s.split('```')
    if len(parts) >= 3:
        print(parts[1])
PY <<'PY_INPUT'
'"'"$(cat "$AI_RESP")"'"'
PY_INPUT
  else
    # fallback native shell: extract between first pair of ```
    awk 'BEGIN{found=0} /```/{if(found==0){found=1; next} else {exit}} found{print}' "$AI_RESP" > "$PATCH_TMP" || true
  fi
else
  echo "No fenced patch found in AI response" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate patch applies cleanly
if ! git apply --check "$PATCH_TMP" > /tmp/ai_patch_check.out 2>&1; then
  echo "AI patch failed git apply --check" >> "$DIAG"
  cat /tmp/ai_patch_check.out >> "$DIAG" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Apply patch
git apply "$PATCH_TMP" || {
  echo "git apply failed" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
}

# ---------- validate after patch ----------
{
  echo "Validating after AI patch..." >> "$VALIDATE_LOG"
  set +e
  go mod tidy >> "$VALIDATE_LOG" 2>&1 || true
  go build ./... >> "$VALIDATE_LOG" 2>&1
  build_exit=$?
  go test ./... >> "$VALIDATE_LOG" 2>&1
  test_exit=$?
  set -e
  echo "build_exit=${build_exit}, test_exit=${test_exit}" >> "$VALIDATE_LOG"
} || true

if [ "${build_exit:-1}" -ne 0 ] || [ "${test_exit:-1}" -ne 0 ]; then
  echo "Validation failed after AI patch. Reverting changes." >> "$DIAG"
  git checkout -- . || true
  cp "$VALIDATE_LOG" "${ART_DIR}/ai-validate.log" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------- commit & push only allowed files ----------
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=("$tf")
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch did not change any allowed target files; aborting." >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/ai-fix-${TIMESTAMP}"
git checkout -b "$BRANCH"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
git config user.name "github-actions[bot]" || true

for f in "${CHANGED_TARGETS[@]}"; do
  git add -- "$f" || true
done
# ensure go.mod/go.sum included if changed
for f in go.mod go.sum; do
  if git status --porcelain | awk '{print $2}' | grep -Fqx "$f"; then
    git add -- "$f" || true
  fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true

if git push --set-upstream origin "$BRANCH" >/dev/null 2>&1; then
  echo "Branch pushed: $BRANCH" >> "$DIAG"
  git diff origin/main.."${BRANCH}" > "$PATCH_AFTER" 2>/dev/null || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  cp "$VALIDATE_LOG" "${ART_DIR}/ai-validate.log" || true
  echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
  exit 0
else
  echo "Failed to push branch $BRANCH" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi
