#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Robust AI refactor driver using a small Python helper to call OpenRouter.
set -euo pipefail

# Re-exec under bash if not running with bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi

# ---------- arg parsing ----------
ARTIFACT_DIR="ci-artifacts/combined"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a) ARTIFACT_DIR="$2"; shift 2 ;;
    *) echo "Warning: unknown arg: $1" >&2; shift ;;
  esac
done

mkdir -p "$ARTIFACT_DIR"

# ---------- init vars ----------
AI_CONTENT=""
BRANCH_OUT=""
TMP_FILES=()

DIAG="$ARTIFACT_DIR/ai-diagnostics.txt"
AI_RAW="$ARTIFACT_DIR/ai-raw-response.json"
AI_RESP="$ARTIFACT_DIR/ai-response.txt"
PATCH_BEFORE="$ARTIFACT_DIR/ai-diff-before.patch"
PATCH_AFTER="$ARTIFACT_DIR/ai-diff-after.patch"
VALIDATE_LOG="$ARTIFACT_DIR/ai-validate.log"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set (secret)}"
: "${GH2_TOKEN:?GH2_TOKEN must be set (secret)}"

# MODEL precedence: env then file
OPENROUTER_MODEL="${OPENROUTER_MODEL:-}"
if [ -z "$OPENROUTER_MODEL" ] && [ -f ".github/ai_model.txt" ]; then
  OPENROUTER_MODEL="$(sed -n '1p' .github/ai_model.txt | tr -d '[:space:]' || true)"
fi
if [ -z "$OPENROUTER_MODEL" ]; then
  echo "ERROR: OPENROUTER_MODEL not set and .github/ai_model.txt missing" | tee "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi

# make git safe in runner
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$(pwd)}" >/dev/null 2>&1 || true

# ensure go env
if ! command -v go >/dev/null 2>&1; then
  echo "go not found in PATH; aborting" | tee -a "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi

GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
mkdir -p "$GOBIN"; export PATH="$GOBIN:$PATH"

# install minimal tools (best-effort)
if ! command -v goimports >/dev/null 2>&1; then
  go install golang.org/x/tools/cmd/goimports@latest || true
fi
if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$GOBIN" v2.5.0 >/dev/null 2>&1 || true
fi

# Save before diff for diagnostics
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

{
  echo "ai_refactor run: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "model: $OPENROUTER_MODEL"
} > "$DIAG"

# Run safe auto-fixes
gofmt -s -w . || true
command -v goimports >/dev/null 2>&1 && goimports -w . || true
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --fix --timeout=10m ./... >> "${ARTIFACT_DIR}/golangci-fix.log" 2>&1 || true
go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

# If safe fixes changed allowed files -> create branch & push; exit (no AI)
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

# Determine whether AI is needed
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
PROMPT_FILE="$(mktemp)"; TMP_FILES+=("$PROMPT_FILE")
cat > "$PROMPT_FILE" <<'PROMPT'
You are an expert Go maintainer. Produce a single unified git diff patch (fenced with triple backticks) that fixes the build/test/lint issues below.
Only modify files if necessary: chachacrypt.go, go.mod, go.sum. Keep changes minimal and safe.
PROMPT
{
  echo ""; echo "=== BUILD OUTPUT ==="; sed -n '1,400p' "${ARTIFACT_DIR}/go-build-output.txt" 2>/dev/null || true
  echo ""; echo "=== TEST OUTPUT ==="; sed -n '1,400p' "${ARTIFACT_DIR}/go-test-output.txt" 2>/dev/null || true
  echo ""; echo "=== LINT STDERR ==="; sed -n '1,400p' "${ARTIFACT_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo ""; echo "=== FILES (first 400 lines) ==="
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && { echo "----- FILE: $f -----"; sed -n '1,400p' "$f"; echo; } || true; done
} >> "$PROMPT_FILE"

# Build a short Python helper for the API call (safe JSON, DNS checks, retries)
PY_CALL="$(mktemp)"; TMP_FILES+=("$PY_CALL")
cat > "$PY_CALL" <<'PYCODE'
#!/usr/bin/env python3
import json,sys,time,os,socket
try:
    import requests
except Exception as e:
    sys.stderr.write("requests missing\n")
    sys.exit(2)

API_URL="https://openrouter.ai/api/v1/chat/completions"
API_KEY=os.environ.get("OPENROUTER_API_KEY")
MODEL=os.environ.get("OPENROUTER_MODEL")
if not API_KEY or not MODEL:
    sys.stderr.write("Missing OPENROUTER_API_KEY or OPENROUTER_MODEL\n")
    sys.exit(2)

prompt_path=sys.argv[1]
with open(prompt_path,"r",encoding="utf-8") as fh:
    user_text = fh.read()

payload={
  "model": MODEL,
  "messages": [
    {"role":"system","content":"You are a senior Go refactoring assistant."},
    {"role":"user","content": user_text}
  ],
  "temperature": 0.2,
  "max_tokens": 32768
}

# DNS check and retry
host="openrouter.ai"
ok=False
for attempt in range(6):
    try:
        socket.gethostbyname(host)
        ok=True
        break
    except Exception:
        time.sleep((attempt+1)*1.5)
if not ok:
    sys.stderr.write("DNS lookup failed for openrouter.ai\n")
    # continue to attempt the request anyway

# Try to POST with retries
headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
attempt=0
while attempt < 6:
    attempt += 1
    try:
        r = requests.post(API_URL, headers=headers, json=payload, timeout=120)
        r.raise_for_status()
        out = r.json()
        sys.stdout.write(json.dumps(out, ensure_ascii=False))
        sys.exit(0)
    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"request error attempt {attempt}: {e}\n")
        time.sleep(attempt * 2.0)
    except ValueError:
        sys.stderr.write("response not json\n")
        sys.stderr.write(r.text if 'r' in locals() else '')
        sys.exit(3)
sys.stderr.write("failed after retries\n")
sys.exit(3)
PYCODE
chmod +x "$PY_CALL"

# Ensure requests is installed for the python helper (best-effort)
if ! python3 -c "import requests" >/dev/null 2>&1; then
  if command -v pip3 >/dev/null 2>&1; then
    python3 -m pip install --upgrade requests >/dev/null 2>&1 || true
  fi
fi

# Run the python caller
RESPONSE_JSON="$(mktemp)"; TMP_FILES+=("$RESPONSE_JSON")
set +e
python3 "$PY_CALL" "$PROMPT_FILE" > "$RESPONSE_JSON" 2> "$DIAG"
PY_EXIT=$?
set -e
cp "$RESPONSE_JSON" "$AI_RAW" || true

if [ "$PY_EXIT" -ne 0 ]; then
  echo "OpenRouter python call failed (exit $PY_EXIT). See $DIAG and $AI_RAW" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Extract content (choices[0].message.content) via python for robustness
EXTRACT_PY="$(mktemp)"; TMP_FILES+=("$EXTRACT_PY")
cat > "$EXTRACT_PY" <<'PY'
import json,sys
try:
    obj=json.load(open(sys.argv[1],'r',encoding='utf-8'))
    choices = obj.get("choices") or []
    if choices:
        c = choices[0]
        if isinstance(c, dict):
            msg = c.get("message",{}) or {}
            content = msg.get("content") or c.get("text") or ""
        else:
            content = ""
    else:
        content = ""
    sys.stdout.write(content or "")
except Exception as e:
    sys.stderr.write("extract error: "+str(e))
    sys.exit(1)
PY
python3 "$EXTRACT_PY" "$RESPONSE_JSON" > "$AI_RESP" 2>> "$DIAG" || true

AI_CONTENT="$(sed -n '1,20000p' "$AI_RESP" || true)"
if [ -z "${AI_CONTENT:-}" ]; then
  echo "AI returned empty content; see $AI_RAW and $DIAG" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Extract fenced patch
PATCH_TMP="$(mktemp)"; TMP_FILES+=("$PATCH_TMP")
EXTRACT_PATCH_PY="$(mktemp)"; TMP_FILES+=("$EXTRACT_PATCH_PY")
cat > "$EXTRACT_PATCH_PY" <<'PY'
import re,sys
s=open(sys.argv[1],'r',encoding='utf-8').read()
m=re.search(r'```(?:diff[^\n]*)?\n(.*?)\n```',s,re.S)
if not m:
    m=re.search(r'```\s*\n(.*?)\n```',s,re.S)
if m:
    print(m.group(1))
else:
    print("",end="")
PY
python3 "$EXTRACT_PATCH_PY" "$AI_RESP" > "$PATCH_TMP" 2>> "$DIAG" || true

if [ ! -s "$PATCH_TMP" ]; then
  echo "No patch extracted from AI response" >> "$DIAG"
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

git apply "$PATCH_TMP" || { echo "git apply failed" >> "$DIAG"; cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true; echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="; exit 0; }

# Validate build & tests after applying patch
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

# Commit allowed files and push branch
CHANGED_NOW="$(git status --porcelain | awk '{print $2}' || true)"
CHANGED_TARGETS=()
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then CHANGED_TARGETS+=("$tf"); fi
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

# Emit PR branch to GITHUB_OUTPUT for create-pull-request action
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT}"
else
  echo "pr_branch=${BR}"
fi

exit 0
 
