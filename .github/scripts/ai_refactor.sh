#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Robust AI refactor script (drop-in replacement).
# - Requires OPENROUTER_API_KEY, GH2_TOKEN and OPENROUTER_MODEL (or .github/ai_model.txt)
# - Writes pr_branch to GITHUB_ACTIONS outputs via GITHUB_OUTPUT.
set -euo pipefail

# Ensure bash features available
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi

# ---------------------------
# Args
# ---------------------------
ARTIFACT_DIR="ci-artifacts/combined"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a) ARTIFACT_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; shift ;;
  esac
done

# Immediately ensure artifact dir exists
mkdir -p "$ARTIFACT_DIR"

# Initialize variables to avoid unbound variable errors
AI_CONTENT=""
PR_BRANCH=""
TMPFILES=()

# Artifact file paths
DIAG="$ARTIFACT_DIR/ai-diagnostics.txt"
AI_RAW="$ARTIFACT_DIR/ai-raw-response.json"
AI_RESP="$ARTIFACT_DIR/ai-response.txt"
PATCH_BEFORE="$ARTIFACT_DIR/ai-diff-before.patch"
PATCH_AFTER="$ARTIFACT_DIR/ai-diff-after.patch"
VALIDATE_LOG="$ARTIFACT_DIR/ai-validate.log"

# Required secrets
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set (repo secret)}"
: "${GH2_TOKEN:?GH2_TOKEN must be set (repo secret)}"

# MODEL precedence: env OPENROUTER_MODEL > .github/ai_model.txt > fail
OPENROUTER_MODEL="${OPENROUTER_MODEL:-}"
if [ -z "$OPENROUTER_MODEL" ] && [ -f ".github/ai_model.txt" ]; then
  OPENROUTER_MODEL="$(sed -n '1p' .github/ai_model.txt | tr -d '[:space:]' || true)"
fi
if [ -z "$OPENROUTER_MODEL" ]; then
  echo "ERROR: OPENROUTER_MODEL not set and .github/ai_model.txt missing" | tee "$DIAG"
  # set empty pr_branch output then exit
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi

# Make git safe
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$(pwd)}" >/dev/null 2>&1 || true

# Ensure GOBIN on PATH
if command -v go >/dev/null 2>&1; then
  GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
  mkdir -p "$GOBIN"
  export PATH="$GOBIN:$PATH"
fi

# Install minimal tools if missing (best-effort)
if ! command -v goimports >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
  go install golang.org/x/tools/cmd/goimports@latest || true
fi
if ! command -v golangci-lint >/dev/null 2>&1; then
  # install pinned v2.5.0 if possible
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$GOBIN" v2.5.0 >/dev/null 2>&1 || true
fi

# Save before-diff of allowed files
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# Diagnostics header
{
  echo "ai_refactor.sh diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "model: $OPENROUTER_MODEL"
} > "$DIAG"

# Run safe auto-fixes
gofmt -s -w . || true
command -v goimports >/dev/null 2>&1 && goimports -w . || true
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --fix --timeout=10m ./... >> "${ARTIFACT_DIR}/golangci-fix.log" 2>&1 || true
go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

# If safe fixes changed allowed files -> commit & push (no AI)
CHANGED_NOW="$(git status --porcelain | awk '{print $2}' || true)"
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    TS="$(date -u +%Y%m%d%H%M%S)"
    BR="ai/auto-fix-${TS}"
    git checkout -b "$BR"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
    git commit -m "[create-pull-request] automated safe fixes" || true
    git push --set-upstream origin "$BR" || true
    echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
    exit 0
  fi
done

# Collect diagnostics
go build ./... > "${ARTIFACT_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ARTIFACT_DIR}/go-test-output.txt" 2>&1 || true
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --out-format json ./... > "${ARTIFACT_DIR}/golangci.runtime.json" 2> "${ARTIFACT_DIR}/golangci.runtime.stderr" || true
fi

# Decide if AI needed
NEED_AI=false
if [ -s "${ARTIFACT_DIR}/go-build-output.txt" ] || [ -s "${ARTIFACT_DIR}/go-test-output.txt" ]; then NEED_AI=true; fi
if [ -f "${ARTIFACT_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ARTIFACT_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|%s|%s' "${TARGET_FILES[0]}" "${TARGET_FILES[1]}" "${TARGET_FILES[2]}")" >/dev/null 2>&1; then NEED_AI=true; fi
fi
if [ "$NEED_AI" = false ]; then
  echo "No relevant issues; exiting." >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Build prompt file
PROMPT_FILE="$(mktemp)"; TMPFILES+=("$PROMPT_FILE")
cat > "$PROMPT_FILE" <<'PROMPT_EOF'
You are an expert Go maintainer. Produce a single unified git diff patch (fenced with triple backticks) that fixes the build/test/lint issues below.
Only modify files if necessary: chachacrypt.go, go.mod, go.sum. Keep behavior and interfaces stable. If modifying go.mod, keep changes minimal.
PROMPT_EOF

{
  echo ""; echo "=== BUILD ==="; sed -n '1,200p' "${ARTIFACT_DIR}/go-build-output.txt" 2>/dev/null || true
  echo ""; echo "=== TEST ==="; sed -n '1,200p' "${ARTIFACT_DIR}/go-test-output.txt" 2>/dev/null || true
  echo ""; echo "=== LINT STDERR ==="; sed -n '1,200p' "${ARTIFACT_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo ""; echo "=== FILES (first 200 lines) ==="
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && { echo "----- FILE: $f -----"; sed -n '1,200p' "$f"; echo; } || true; done
} >> "$PROMPT_FILE"

# Build JSON payload safely (jq preferred, python fallback)
PAYLOAD_FILE="$(mktemp)"; TMPFILES+=("$PAYLOAD_FILE")
if command -v jq >/dev/null 2>&1; then
  jq -n --arg model "$OPENROUTER_MODEL" \
        --arg sys "You are a precise Go patch generator. Provide a single fenced diff patch." \
        --arg usr "$(sed -n '1,20000p' "$PROMPT_FILE")" \
        '{model:$model, messages:[{role:"system",content:$sys},{role:"user",content:$usr}], temperature:0.0, max_tokens:32768}' > "$PAYLOAD_FILE"
else
  PY_PAYLOAD="$(mktemp)"; TMPFILES+=("$PY_PAYLOAD")
  cat > "$PY_PAYLOAD" <<'PYCODE'
import json,sys
model=sys.argv[1]; prompt_path=sys.argv[2]
with open(prompt_path,'r',encoding='utf-8') as fh:
    user=fh.read()
payload={"model":model,"messages":[{"role":"system","content":"You are a precise Go patch generator. Provide a single fenced diff patch."},{"role":"user","content":user}],"temperature":0.0,"max_tokens":32768}
json.dump(payload,sys.stdout,ensure_ascii=False)
PYCODE
  if command -v python3 >/dev/null 2>&1; then
    python3 "$PY_PAYLOAD" "$OPENROUTER_MODEL" "$PROMPT_FILE" > "$PAYLOAD_FILE"
  else
    python "$PY_PAYLOAD" "$OPENROUTER_MODEL" "$PROMPT_FILE" > "$PAYLOAD_FILE"
  fi
fi

# Call OpenRouter
RESPONSE_TMP="$(mktemp)"; TMPFILES+=("$RESPONSE_TMP")
HTTP_CODE=$(curl -sS -X POST "https://api.openrouter.ai/v1/chat/completions" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @"$PAYLOAD_FILE" -w "%{http_code}" -o "$RESPONSE_TMP" ) || true

cp "$RESPONSE_TMP" "$AI_RAW" || true

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "OpenRouter API returned HTTP $HTTP_CODE" >> "$DIAG"
  cat "$RESPONSE_TMP" >> "$DIAG" || true
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Extract AI content robustly
if command -v jq >/dev/null 2>&1; then
  AI_CONTENT="$(jq -r '.choices[0].message.content // .choices[0].text // ""' "$RESPONSE_TMP" 2>/dev/null || true)"
else
  PY_EXTRACT="$(mktemp)"; TMPFILES+=("$PY_EXTRACT")
  cat > "$PY_EXTRACT" <<'PYEX'
import json,sys
try:
  obj=json.load(open(sys.argv[1],'r',encoding='utf-8'))
  choices=obj.get('choices') or []
  if choices:
    c=choices[0]
    out=c.get('message',{}).get('content') or c.get('text') or ""
  else:
    out=""
  sys.stdout.write(out or "")
except Exception:
  sys.stdout.write("")
PYEX
  if command -v python3 >/dev/null 2>&1; then
    AI_CONTENT="$(python3 "$PY_EXTRACT" "$RESPONSE_TMP" 2>/dev/null || true)"
  else
    AI_CONTENT="$(python "$PY_EXTRACT" "$RESPONSE_TMP" 2>/dev/null || true)"
  fi
fi

# Persist AI content and fail safely if empty
printf "%s\n" "$AI_CONTENT" > "$AI_RESP" || true
if [ -z "${AI_CONTENT:-}" ]; then
  echo "AI returned empty content; see $AI_RAW and $DIAG" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Extract fenced diff from AI_CONTENT using python (robust)
PATCH_TMP="$(mktemp)"; TMPFILES+=("$PATCH_TMP")
PY_EXTRACT_PATCH="$(mktemp)"; TMPFILES+=("$PY_EXTRACT_PATCH")
cat > "$PY_EXTRACT_PATCH" <<'PYPATCH'
import re,sys
s=open(sys.argv[1],'r',encoding='utf-8').read()
m=re.search(r'```(?:diff[^\n]*)?\n(.*?)\n```',s,re.S)
if not m:
  m=re.search(r'```\s*\n(.*?)\n```',s,re.S)
if m:
  print(m.group(1))
else:
  print("",end="")
PYPATCH
if command -v python3 >/dev/null 2>&1; then
  python3 "$PY_EXTRACT_PATCH" "$AI_RESP" > "$PATCH_TMP" || true
else
  python "$PY_EXTRACT_PATCH" "$AI_RESP" > "$PATCH_TMP" || true
fi

if [ ! -s "$PATCH_TMP" ]; then
  echo "No patch extracted from AI response" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate patch
if ! git apply --check "$PATCH_TMP" > /tmp/ai_patch_check.out 2>&1; then
  echo "AI patch failed git apply --check" >> "$DIAG"
  cat /tmp/ai_patch_check.out >> "$DIAG" || true
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

git apply "$PATCH_TMP" || {
  echo "git apply failed" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
}

# Validate build/test after applying patch
set +e
go mod tidy >> "$VALIDATE_LOG" 2>&1 || true
go build ./... >> "$VALIDATE_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$VALIDATE_LOG" 2>&1
TEST_EXIT=$?
set -e

if [ "$BUILD_EXIT" -ne 0 ] || [ "$TEST_EXIT" -ne 0 ]; then
  echo "Validation failed after AI patch; reverting" >> "$DIAG"
  git checkout -- . || true
  cp "$VALIDATE_LOG" "${ARTIFACT_DIR}/ai-validate.log" || true
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Commit only allowed files and push branch
CHANGED_NOW="$(git status --porcelain | awk '{print $2}' || true)"
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=("$tf")
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch did not change allowed target files" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

TS="$(date -u +%Y%m%d%H%M%S)"
BR="ai/ai-fix-${TS}"
git checkout -b "$BR"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
git config user.name "github-actions[bot]" || true

for f in "${CHANGED_TARGETS[@]}"; do git add -- "$f" || true; done
for f in go.mod go.sum; do
  if git status --porcelain | awk '{print $2}' | grep -Fqx "$f"; then git add -- "$f" || true; fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true
git push --set-upstream origin "$BR" || true

git diff origin/main.."${BR}" > "$PATCH_AFTER" 2>/dev/null || true
cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
cp "$VALIDATE_LOG" "${ARTIFACT_DIR}/ai-validate.log" || true

# Emit pr_branch to GITHUB_OUTPUT (if available)
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "pr_branch=${BR}" >> "$GITHUB_OUTPUT"
else
  # fallback: print to stdout (create-pull-request expects step output)
  echo "pr_branch=${BR}"
fi

exit 0
 
