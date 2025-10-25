#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Robust AI refactor script — safe JSON, explicit model selection, artifact handling, validation.
set -euo pipefail

# Re-exec under bash if necessary
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi

# ---------- Arguments ----------
ARTIFACT_DIR="ci-artifacts/combined"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a)
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      shift
      ;;
  esac
done

# ---------- Environment checks ----------
WORKDIR="${GITHUB_WORKSPACE:-$(pwd)}"
cd "$WORKDIR"

# Ensure artifact dir exists before anything else (fixes missing-file errors)
mkdir -p "$ARTIFACT_DIR"

# Files & logs
DIAG="${ARTIFACT_DIR}/ai-diagnostics.txt"
AI_RAW="${ARTIFACT_DIR}/ai-raw-response.json"
AI_RESP="${ARTIFACT_DIR}/ai-response.txt"
PATCH_BEFORE="${ARTIFACT_DIR}/ai-diff-before.patch"
PATCH_AFTER="${ARTIFACT_DIR}/ai-diff-after.patch"
VALIDATE_LOG="${ARTIFACT_DIR}/ai-validate.log"

# Required secrets
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set as a repo secret}"
: "${GH2_TOKEN:?GH2_TOKEN must be set as a repo secret}"

# Model selection precedence:
# 1) OPENROUTER_MODEL env (recommended)
# 2) .github/ai_model.txt file in repo (if present)
# If neither present, exit with error (so you don't accidentally use a fallback)
OPENROUTER_MODEL="${OPENROUTER_MODEL:-}"
if [ -z "$OPENROUTER_MODEL" ] && [ -f ".github/ai_model.txt" ]; then
  # read single-line model name from file
  OPENROUTER_MODEL="$(sed -n '1p' .github/ai_model.txt | tr -d '[:space:]' || true)"
fi
if [ -z "$OPENROUTER_MODEL" ]; then
  echo "ERROR: OPENROUTER_MODEL not set as env and .github/ai_model.txt not present. Set the exact model you want." | tee "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi

# Mark repo safe directory for git in runner environments
git config --global --add safe.directory "$WORKDIR" >/dev/null 2>&1 || true

# Ensure origin uses GH2_TOKEN to push branches (safe fallback)
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY:-$(git rev-parse --show-toplevel | xargs basename)}.git" >/dev/null 2>&1 || true
fi

# ---------- Helper detection ----------
HAS_JQ=false
HAS_PY=false
if command -v jq >/dev/null 2>&1; then HAS_JQ=true; fi
if command -v python3 >/dev/null 2>&1; then HAS_PY=true; elif command -v python >/dev/null 2>&1; then HAS_PY=true; fi

# ---------- Save before-diff ----------
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# Diagnosis header
{
  echo "ai_refactor diagnostics: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "workspace: $WORKDIR"
  echo "openrouter_model: $OPENROUTER_MODEL"
} > "$DIAG"

# ---------- Ensure Go tools available ----------
if ! command -v go >/dev/null 2>&1; then
  echo "go not found in PATH; aborting" >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Ensure GOBIN / PATH updated for go install
GOBIN="${GOBIN:-$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin}"
mkdir -p "$GOBIN"
export PATH="$GOBIN:$PATH"

# Install goimports if missing
if ! command -v goimports >/dev/null 2>&1; then
  echo "Installing goimports to $GOBIN" >> "$DIAG"
  if go install golang.org/x/tools/cmd/goimports@latest >/dev/null 2>&1; then
    echo "goimports installed" >> "$DIAG"
  else
    echo "goimports install failed (non-fatal)" >> "$DIAG"
  fi
fi

# Install golangci-lint if missing (best-effort; version pinned to v2.5.0)
if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "Installing golangci-lint v2.5.0" >> "$DIAG"
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$GOBIN" v2.5.0 >/dev/null 2>&1 || true
fi

# ---------- Safe automatic fixes ----------
{
  echo "Running safe auto-fixes..." >> "$DIAG"
  gofmt -s -w . || true
  if command -v goimports >/dev/null 2>&1; then
    goimports -w . || true
  fi
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=10m ./... >> "${ARTIFACT_DIR}/golangci-fix.log" 2>&1 || true
  fi
  go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true
} || true

# If safe fixes changed allowed files, commit/push and exit
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
    BRANCH="ai/auto-fix-${TIMESTAMP}"
    git checkout -b "$BRANCH"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    git push --set-upstream origin "$BRANCH" || true
    git diff origin/main.."${BRANCH}" > "$PATCH_AFTER" 2>/dev/null || true
    echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
    exit 0
  fi
done

# ---------- Collect diagnostics ----------
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --out-format json ./... > "${ARTIFACT_DIR}/golangci.runtime.json" 2> "${ARTIFACT_DIR}/golangci.runtime.stderr" || true
fi

go build ./... > "${ARTIFACT_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ARTIFACT_DIR}/go-test-output.txt" 2>&1 || true

NEED_AI=false
if [ -s "${ARTIFACT_DIR}/go-build-output.txt" ] || [ -s "${ARTIFACT_DIR}/go-test-output.txt" ]; then
  NEED_AI=true
fi
if [ -f "${ARTIFACT_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ARTIFACT_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|%s|%s' "${TARGET_FILES[0]}" "${TARGET_FILES[1]}" "${TARGET_FILES[2]}")" >/dev/null 2>&1; then
    NEED_AI=true
  fi
fi

if [ "$NEED_AI" = false ]; then
  echo "No relevant issues; nothing for AI." >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Build prompt file safely
PROMPT_FILE="$(mktemp)"
cat > "$PROMPT_FILE" <<'PROMPT_EOF'
You are an expert Go maintainer. Produce a single unified git patch (diff) enclosed in triple backticks that fixes the build / test / lint issues below.
Only change files if necessary: chachacrypt.go, go.mod, go.sum. Prefer minimal, safe changes. If modifying go.mod, keep version bumps minimal and run 'go mod tidy'.
PROMPT_EOF

{
  echo ""; echo "=== LINT OUTPUT ==="; sed -n '1,200p' "${ARTIFACT_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo ""; echo "=== BUILD OUTPUT ==="; sed -n '1,200p' "${ARTIFACT_DIR}/go-build-output.txt" 2>/dev/null || true
  echo ""; echo "=== TEST OUTPUT ==="; sed -n '1,200p' "${ARTIFACT_DIR}/go-test-output.txt" 2>/dev/null || true
  echo ""; echo "=== FILE CONTEXT (first 200 lines each) ==="
  for f in "${TARGET_FILES[@]}"; do if [ -f "$f" ]; then echo "----- FILE: $f -----"; sed -n '1,200p' "$f"; fi; done
} >> "$PROMPT_FILE"

# ---------- Build payload safely ----------
PAYLOAD_FILE="$(mktemp)"
if command -v jq >/dev/null 2>&1; then
  jq -n --arg model "$OPENROUTER_MODEL" \
        --arg sys "You are a precise Go patch generator. Provide a single fenced patch." \
        --arg usr "$(sed -n '1,20000p' "$PROMPT_FILE")" \
        '{model:$model, messages:[{role:"system",content:$sys},{role:"user",content:$usr}], temperature:0.0, max_tokens:32768}' > "$PAYLOAD_FILE"
elif command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
  # python fallback
  (python3 - <<PY 2>/dev/null || python - <<PY
import json,sys
model = "$OPENROUTER_MODEL"
sys_msg = "You are a precise Go patch generator. Provide a single fenced patch."
user_msg = open("$PROMPT_FILE","r",encoding="utf-8").read()
payload = {"model": model, "messages":[{"role":"system","content":sys_msg},{"role":"user","content":user_msg}], "temperature":0.0, "max_tokens":32768}
json.dump(payload, sys.stdout, ensure_ascii=False)
PY
  ) > "$PAYLOAD_FILE"
else
  echo "jq or python is required to safely build the payload. Aborting." >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------- Call OpenRouter ----------
RESPONSE_TMP="$(mktemp)"
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

# Extract AI content
AI_CONTENT=""
if command -v jq >/dev/null 2>&1; then
  AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // ""' "$RESPONSE_TMP" 2>/dev/null || true)
elif command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
  AI_CONTENT=$(python3 - <<PY 2>/dev/null || python - <<PY 2>/dev/null
import json,sys
try:
    obj=json.load(open("$RESPONSE_TMP","r",encoding="utf-8"))
    chs = obj.get("choices") or []
    if chs:
        c=chs[0]
        out = c.get("message",{}).get("content") or c.get("text") or ""
    else:
        out = ""
    sys.stdout.write(out or "")
except Exception:
    sys.stdout.write("")
PY
)
else
  AI_CONTENT=$(sed -n '1,20000p' "$RESPONSE_TMP" 2>/dev/null || true)
fi

echo "$AI_CONTENT" > "$AI_RESP"

if [ -z "${AI_CONTENT:-}" ]; then
  echo "AI returned empty content; see $AI_RAW and $DIAG" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# ---------- Extract fenced patch robustly ----------
PATCH_TMP="$(mktemp)"
PATCH_EXTRACTED=""
if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
  PATCH_EXTRACTED=$(python3 - <<PY 2>/dev/null || python - <<PY 2>/dev/null
import re,sys
s = open("$AI_RESP","r",encoding="utf-8").read()
m = re.search(r'```(?:diff[^\n]*\n)?(.*?)\n```', s, re.S)
if not m:
    m = re.search(r'```\\s*\\n(.*?)\\n```', s, re.S)
if m:
    print(m.group(1))
else:
    print("", end="")
PY
)
  printf "%s\n" "$PATCH_EXTRACTED" > "$PATCH_TMP" || true
else
  awk 'BEGIN{found=0} /```/{if(found==0){found=1; next} else {exit}} found{print}' "$AI_RESP" > "$PATCH_TMP" || true
fi

if [ ! -s "$PATCH_TMP" ]; then
  echo "No patch could be extracted from AI response" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Validate patch applies
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

# Validate after patch
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
CHANGED_NOW=$(git status --porcelain | awk '{print $2}' || true)
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    CHANGED_TARGETS+=("$tf")
  fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "No allowed target files changed by AI patch" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BRANCH="ai/ai-fix-${TIMESTAMP}"
git checkout -b "$BRANCH"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
git config user.name "github-actions[bot]" || true

for f in "${CHANGED_TARGETS[@]}"; do git add -- "$f" || true; done
for f in go.mod go.sum; do
  if git status --porcelain | awk '{print $2}' | grep -Fqx "$f"; then git add -- "$f" || true; fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true
git push --set-upstream origin "$BRANCH" || true

git diff origin/main.."${BRANCH}" > "$PATCH_AFTER" 2>/dev/null || true
cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
cp "$VALIDATE_LOG" "${ARTIFACT_DIR}/ai-validate.log" || true

echo "pr_branch=${BRANCH}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BRANCH}"
exit 0
