#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Robust drop-in replacement that avoids unbound-variable errors and fragile JSON/string building.
set -euo pipefail

# Re-exec under bash if not using bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi

# --------- args ----------
ARTIFACTS_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done
if [ -z "$ARTIFACTS_DIR" ]; then
  echo "Usage: $0 --artifacts <path>" >&2
  exit 1
fi

# --------- env & workspace ----------
WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
ART_DIR="${WORKDIR}/${ARTIFACTS_DIR}"
mkdir -p "$ART_DIR"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

cd "$WORKDIR"

# Make git safe
git config --global --add safe.directory "$WORKDIR" >/dev/null 2>&1 || true

# Ensure origin uses GH2_TOKEN (safe fallback; workflow may already set this)
git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" >/dev/null 2>&1 || true
git fetch origin --prune --tags >/dev/null 2>&1 || true

# --------- constants and artifact files ----------
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
DIAG="${ART_DIR}/ai-diagnostics.txt"
AI_RAW="${ART_DIR}/ai-raw-response.json"
AI_RESP="${ART_DIR}/ai-response.txt"
PATCH_BEFORE="${ART_DIR}/ai-diff-before.patch"
PATCH_AFTER="${ART_DIR}/ai-diff-after.patch"
VALIDATE_LOG="${ART_DIR}/ai-validate.log"

# ensure temp files cleaned up
TMPFILES=()
cleanup() {
  for f in "${TMPFILES[@]:-}"; do
    [ -f "$f" ] && rm -f "$f" || true
  done
}
trap cleanup EXIT

# header
{
  echo "ai_refactor.sh diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY}"
  echo "workspace: ${WORKDIR}"
  echo
} > "$DIAG"

# save before-diff of target files
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# --------- helpers availability ----------
HAS_JQ=false
HAS_PY=false
if command -v jq >/dev/null 2>&1; then HAS_JQ=true; fi
if command -v python3 >/dev/null 2>&1; then HAS_PY=true; elif command -v python >/dev/null 2>&1; then HAS_PY=true; fi

# ensure go exists
if ! command -v go >/dev/null 2>&1; then
  echo "go not found in PATH; aborting" >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ensure GOBIN on PATH
GOBIN="${GOBIN:-$HOME/go/bin}"
mkdir -p "$GOBIN"
export GOBIN
case ":$PATH:" in *":$GOBIN:"*) ;; *) PATH="$GOBIN:$PATH" ;; esac

# install goimports if missing
if ! command -v goimports >/dev/null 2>&1; then
  echo "goimports missing; attempting install" >> "$DIAG"
  if go install golang.org/x/tools/cmd/goimports@latest >/dev/null 2>&1; then
    echo "goimports installed" >> "$DIAG"
    PATH="$GOBIN:$PATH"
  else
    echo "goimports install failed (non-fatal)" >> "$DIAG"
  fi
fi

if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "golangci-lint not found; --fix step will be skipped" >> "$DIAG"
fi

# --------- safe auto-fixes ----------
{
  echo "Running safe auto-fixes..." >> "$DIAG"
  gofmt -s -w . || true
  if command -v goimports >/dev/null 2>&1; then goimports -w . || true; fi
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=10m ./... >> "${ART_DIR}/golangci-fix.log" 2>&1 || true
  fi
  go mod tidy >> "${ART_DIR}/go-mod-tidy.log" 2>&1 || true
} || true

# if auto-fix changed targets -> commit & push branch and exit
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    TS=$(date -u +%Y%m%d%H%M%S)
    BR="ai/auto-fix-${TS}"
    git checkout -b "$BR"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
    git commit -m "[create-pull-request] automated safe fixes" || true
    if git push --set-upstream origin "$BR" >/dev/null 2>&1; then
      echo "Safe-fix branch pushed: $BR" >> "$DIAG"
      git diff origin/main.."${BR}" > "$PATCH_AFTER" 2>/dev/null || true
      cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
      echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
      exit 0
    else
      echo "Failed to push safe-fix branch $BR" >> "$DIAG"
      cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
      echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
      exit 0
    fi
  fi
done

# --------- collect diagnostics for AI ----------
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --out-format json ./... > "${ART_DIR}/golangci.runtime.json" 2> "${ART_DIR}/golangci.runtime.stderr" || true
fi
go build ./... > "${ART_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ART_DIR}/go-test-output.txt" 2>&1 || true

NEED_AI=false
if [ -s "${ART_DIR}/go-build-output.txt" ] || [ -s "${ART_DIR}/go-test-output.txt" ]; then NEED_AI=true; fi
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

# --------- build safe prompt file ----------
PROMPT_FILE="$(mktemp)"; TMPFILES+=("$PROMPT_FILE")
{
  echo "You are an expert Go maintainer. Produce a single unified git diff patch (fenced with ``` ) that fixes the lint/build/test issues below."
  echo "Only modify: ${TARGET_FILES[*]}. Keep changes minimal and safe."
  echo
  echo "=== LINT ==="
  sed -n '1,200p' "${ART_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo
  echo "=== BUILD ==="
  sed -n '1,200p' "${ART_DIR}/go-build-output.txt" 2>/dev/null || true
  echo
  echo "=== TEST ==="
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
} > "$PROMPT_FILE"

# --------- prepare JSON payload in a file (jq preferred, python fallback) ----------
API_URL="https://api.openrouter.ai/v1/chat/completions"
MODEL="minimax/minimax-m2:free"
PAYLOAD_FILE="$(mktemp)"; TMPFILES+=("$PAYLOAD_FILE")

if [ "$HAS_JQ" = true ]; then
  jq -n --arg model "$MODEL" \
        --arg sys "You are an expert Go code patch generator. Provide exactly one fenced diff patch." \
        --arg usr "$(sed -n '1,20000p' "$PROMPT_FILE")" \
        '{model:$model, messages:[{role:"system",content:$sys},{role:"user",content:$usr}], temperature:0.0, max_tokens:32768}' > "$PAYLOAD_FILE"
elif [ "$HAS_PY" = true ]; then
  # Python will safely encode the prompt text into JSON
  python3 - <<PY > "$PAYLOAD_FILE" || python - <<PY > "$PAYLOAD_FILE"
import json
MODEL="${MODEL}"
sys_txt="You are an expert Go code patch generator. Provide exactly one fenced diff patch."
with open("${PROMPT_FILE}","r",encoding="utf-8") as fh:
    user = fh.read()
payload = {
  "model": MODEL,
  "messages": [
    {"role":"system","content": sys_txt},
    {"role":"user","content": user}
  ],
  "temperature": 0.0,
  "max_tokens": 32768
}
json.dump(payload, sys.stdout, ensure_ascii=False)
PY
else
  echo "Neither jq nor python present to build JSON payload; aborting." >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# --------- call OpenRouter ----------
RESPONSE_TMP="$(mktemp)"; TMPFILES+=("$RESPONSE_TMP")
HTTP_CODE=$(curl -sS -X POST "$API_URL" -H "Authorization: Bearer ${OPENROUTER_API_KEY}" -H "Content-Type: application/json" -d @"$PAYLOAD_FILE" -w "%{http_code}" -o "$RESPONSE_TMP" )

cp "$RESPONSE_TMP" "$AI_RAW" || true

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "OpenRouter API returned HTTP $HTTP_CODE" >> "$DIAG"
  cat "$RESPONSE_TMP" >> "$DIAG" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# --------- extract AI_CONTENT (jq preferred, python fallback, or empty) ----------
AI_CONTENT=""
if [ "$HAS_JQ" = true ]; then
  AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // ""' "$RESPONSE_TMP" 2>/dev/null || true)
elif [ "$HAS_PY" = true ]; then
  AI_CONTENT=$(python3 - <<PY 2>/dev/null || python - <<PY 2>/dev/null
import json,sys
try:
    obj=json.load(open("$RESPONSE_TMP","r",encoding="utf-8"))
    out=""
    chs = obj.get("choices") or []
    if chs:
        c = chs[0]
        if isinstance(c, dict):
            out = c.get("message",{}).get("content") or c.get("text") or ""
    sys.stdout.write(out or "")
except Exception:
    sys.stdout.write("")
PY
)
else
  AI_CONTENT=$(sed -n '1,20000p' "$RESPONSE_TMP" 2>/dev/null || true)
fi

echo "$AI_CONTENT" > "$AI_RESP"

# If AI_CONTENT empty => record diagnostics and exit
if [ -z "${AI_CONTENT:-}" ]; then
  echo "AI returned empty content" >> "$DIAG"
  cp "$RESPONSE_TMP" "$AI_RAW" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# --------- extract fenced patch robustly (python preferred, awk fallback) ----------
PATCH_TMP="$(mktemp)"; TMPFILES+=("$PATCH_TMP")
PATCH_CONTENT=""

if [ "$HAS_PY" = true ]; then
  PATCH_CONTENT=$(python3 - <<'PY' 2>/dev/null || python - <<'PY' 2>/dev/null
import re,sys
s = open("$AI_RESP", "r", encoding="utf-8").read()
m = re.search(r'```(?:diff[^\n]*)?\n(.*?)\n```', s, re.S)
if not m:
    # try any fenced block
    m = re.search(r'```\s*\n(.*?)\n```', s, re.S)
if m:
    sys.stdout.write(m.group(1))
else:
    sys.stdout.write("")
PY
)
  printf "%s\n" "$PATCH_CONTENT" > "$PATCH_TMP"
else
  # fallback: awk to get content between first pair of ```
  awk 'BEGIN{found=0} /```/{if(found==0){found=1; next} else {exit}} found{print}' "$AI_RESP" > "$PATCH_TMP" || true
fi

if [ ! -s "$PATCH_TMP" ]; then
  echo "No patch extracted from AI response" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# --------- validate patch applies cleanly ----------
if ! git apply --check "$PATCH_TMP" > /tmp/ai_patch_check.out 2>&1; then
  echo "AI patch failed git apply --check" >> "$DIAG"
  cat /tmp/ai_patch_check.out >> "$DIAG" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

git apply "$PATCH_TMP" || {
  echo "git apply failed" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
}

# --------- validate build/test after patch ----------
build_exit=0; test_exit=0
{
  set +e
  go mod tidy >> "$VALIDATE_LOG" 2>&1 || true
  go build ./... >> "$VALIDATE_LOG" 2>&1
  build_exit=$?
  go test ./... >> "$VALIDATE_LOG" 2>&1
  test_exit=$?
  set -e
} || true

if [ "${build_exit:-1}" -ne 0 ] || [ "${test_exit:-1}" -ne 0 ]; then
  echo "Validation failed after AI patch. Reverting." >> "$DIAG"
  git checkout -- . || true
  cp "$VALIDATE_LOG" "${ART_DIR}/ai-validate.log" || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# --------- commit & push only allowed files ----------
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then CHANGED_TARGETS+=("$tf"); fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch did not change any allowed target files; abort." >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

TS=$(date -u +%Y%m%d%H%M%S)
BR="ai/ai-fix-${TS}"
git checkout -b "$BR"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
git config user.name "github-actions[bot]" || true

for f in "${CHANGED_TARGETS[@]}"; do git add -- "$f" || true; done
for f in go.mod go.sum; do
  if git status --porcelain | awk '{print $2}' | grep -Fqx "$f"; then git add -- "$f" || true; fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true

if git push --set-upstream origin "$BR" >/dev/null 2>&1; then
  echo "Branch pushed: $BR" >> "$DIAG"
  git diff origin/main.."${BR}" > "$PATCH_AFTER" 2>/dev/null || true
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  cp "$VALIDATE_LOG" "${ART_DIR}/ai-validate.log" || true
  echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
  exit 0
else
  echo "Failed to push branch $BR" >> "$DIAG"
  cp "$DIAG" "${ART_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi
