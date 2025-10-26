#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Robust AI refactor driver with safe branch naming and improved diagnostics.
# Requirements (repo secrets): OPENROUTER_API_KEY, GH2_TOKEN
# Optional: OPENROUTER_MODEL (env) or .github/ai_model.txt
set -euo pipefail

# re-exec under bash if needed
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

# -------------------------
# simple arg parsing
ARTIFACT_DIR="ci-artifacts/combined"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a) ARTIFACT_DIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$ARTIFACT_DIR"

# -------------------------
# artifact paths
DIAG="$ARTIFACT_DIR/ai-diagnostics.txt"
AI_RAW="$ARTIFACT_DIR/ai-raw-response.json"
AI_RESP="$ARTIFACT_DIR/ai-response.txt"
VALIDATE_LOG="$ARTIFACT_DIR/ai-validate.log"
PATCH_BEFORE="$ARTIFACT_DIR/ai-diff-before.patch"
PATCH_AFTER="$ARTIFACT_DIR/ai-diff-after.patch"

# -------------------------
# required secrets/env
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set (secret)}"
: "${GH2_TOKEN:?GH2_TOKEN must be set (secret)}"

OPENROUTER_MODEL="${OPENROUTER_MODEL:-}"
if [ -z "$OPENROUTER_MODEL" ] && [ -f ".github/ai_model.txt" ]; then
  OPENROUTER_MODEL="$(sed -n '1p' .github/ai_model.txt | tr -d '[:space:]' || true)"
fi
if [ -z "$OPENROUTER_MODEL" ]; then
  echo "ERROR: OPENROUTER_MODEL not set and .github/ai_model.txt missing" | tee "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi

# -------------------------
# safety: git safe dir for runners
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$(pwd)}" >/dev/null 2>&1 || true

# ensure go present
if ! command -v go >/dev/null 2>&1; then
  echo "go not found; aborting" | tee -a "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi
GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
mkdir -p "$GOBIN"; export PATH="$GOBIN:$PATH"

# -------------------------
# helper: safe branch name generator
# Allowed set per git: [A-Za-z0-9/_-.], avoid leading/trailing dots, no spaces, no colon.
safe_branch() {
  local prefix="$1" version="$2" ts
  # timestamp in UTC, compact
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  # sanitize version: replace any non alnum or dot with underscore; replace dots with dots are ok,
  # but preventing accidental slashes etc
  version_safe="$(echo "$version" | tr -c 'A-Za-z0-9._-' '_')"
  # assemble branch name
  echo "${prefix}-${version_safe}-${ts}"
}

# write diag header
{
  echo "ai_refactor run: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "model: $OPENROUTER_MODEL"
} > "$DIAG"

# Target files allowed to change
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

# -------------------------
# Step 0: check latest Go patch version (canonical source)
# We use https://go.dev/VERSION?m=text which returns e.g. "go1.25.3"
LATEST_GO_FULL="$(curl -fsS https://go.dev/VERSION?m=text || true)"
LATEST_GO=""
if [ -n "$LATEST_GO_FULL" ]; then
  LATEST_GO="${LATEST_GO_FULL#go}"   # e.g. "1.25.3"
fi

# semantic compare helper: returns 0 if a >= b (a and b like "1.25.3")
ver_ge() {
  IFS='.' read -r -a A <<< "$1"
  IFS='.' read -r -a B <<< "$2"
  for i in 0 1 2; do
    ai=${A[i]:-0}; bi=${B[i]:-0}
    if ((10#$ai > 10#$bi)); then return 0; fi
    if ((10#$ai < 10#$bi)); then return 1; fi
  done
  return 0
}

if [ -f go.mod ] && [ -n "$LATEST_GO" ]; then
  CUR_GO="$(awk '/^go /{print $2; exit}' go.mod || true)"
  if [ -n "$CUR_GO" ] && ! ver_ge "$CUR_GO" "$LATEST_GO"; then
    # Create a safe branch that bumps go directive and push it immediately.
    echo "Detected go.mod go directive $CUR_GO < latest $LATEST_GO" >> "$DIAG"

    # Create a conservative updated go.mod (replace first 'go ' line)
    cp go.mod "${ARTIFACT_DIR}/go.mod.prebump" || true
    awk -v ng="$LATEST_GO" 'BEGIN{done=0} { if (!done && $1=="go") { print "go " ng; done=1; next } print }' go.mod > go.mod.tmp && mv go.mod.tmp go.mod || true

    # Run tidy to keep go.sum consistent (best-effort)
    go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

    # Create branch name safely
    BR="$(safe_branch "ai/go-bump" "$LATEST_GO")"
    # ensure branch format accepted by git
    if ! git check-ref-format --branch "$BR" >/dev/null 2>&1; then
      # fallback simple branch name
      BR="ai/go-bump-$(date -u +%Y%m%dT%H%M%SZ)"
    fi

    # create branch and push
    git checkout -b "$BR"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    git add go.mod go.sum || true
    git commit -m "[create-pull-request] bump go directive to ${LATEST_GO}" || true

    # set remote to use GH2_TOKEN only when available and safe
    if [ -n "${GH2_TOKEN:-}" ]; then
      # remote URL safe update
      repo="${GITHUB_REPOSITORY:-}"
      if [ -n "$repo" ]; then
        git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${repo}.git" >/dev/null 2>&1 || true
      fi
    fi

    # push branch
    git push --set-upstream origin "$BR" || {
      echo "Warning: git push failed for branch $BR" >> "$DIAG"
    }

    # output pr_branch
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT}"
    else
      echo "pr_branch=${BR}"
    fi
    exit 0
  else
    echo "go.mod go directive up-to-date (cur: ${CUR_GO:-none}, latest: ${LATEST_GO:-unknown})" >> "$DIAG"
  fi
fi

# -------------------------
# Step 1: safe auto-fixes (formatting and lint --fix)
gofmt -s -w . || true
if ! command -v goimports >/dev/null 2>&1; then
  go install golang.org/x/tools/cmd/goimports@latest || true
fi
command -v goimports >/dev/null 2>&1 && goimports -w . || true

if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$GOBIN" v2.5.0 >/dev/null 2>&1 || true
fi
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --fix --timeout=10m ./... >> "${ARTIFACT_DIR}/golangci-fix.log" 2>&1 || true
go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

# If safe fixes touched allowed files -> branch and push
CHANGED_NOW="$(git status --porcelain | awk '{print $2}' || true)"
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    TS="$(date -u +%Y%m%dT%H%M%SZ)"
    BR="$(safe_branch "ai/auto-fix" "$TS")"
    git checkout -b "$BR"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    [ -n "${GH2_TOKEN:-}" ] && git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" >/dev/null 2>&1 || true
    git push --set-upstream origin "$BR" || true
    if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT}"; else echo "pr_branch=${BR}"; fi
    exit 0
  fi
done

# -------------------------
# Step 2: collect diagnostics (build/test/lint)
go build ./... > "${ARTIFACT_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ARTIFACT_DIR}/go-test-output.txt" 2>&1 || true
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --timeout=10m --out-format json ./... > "${ARTIFACT_DIR}/golangci.runtime.json" 2> "${ARTIFACT_DIR}/golangci.runtime.stderr" || true

NEED_AI=false
if [ -s "${ARTIFACT_DIR}/go-build-output.txt" ] || [ -s "${ARTIFACT_DIR}/go-test-output.txt" ]; then NEED_AI=true; fi
if [ -f "${ARTIFACT_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ARTIFACT_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|%s|%s' "${TARGET_FILES[0]}" "${TARGET_FILES[1]}" "${TARGET_FILES[2]}")" >/dev/null 2>&1; then NEED_AI=true; fi
fi
if [ "$NEED_AI" = false ]; then
  echo "No relevant issues; nothing for AI." >> "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# -------------------------
# Step 3: prepare prompt file
PROMPT_FILE="$(mktemp)"
cat > "$PROMPT_FILE" <<'PROMPT_EOF'
You are an expert Go maintainer. Produce a single unified git diff (patch) enclosed in triple backticks that fixes the build/test/lint issues below.
Only modify files if necessary: chachacrypt.go, go.mod, go.sum. Keep changes minimal and safe.
PROMPT_EOF
{
  echo ""; echo "=== BUILD OUTPUT ==="; sed -n '1,300p' "${ARTIFACT_DIR}/go-build-output.txt" 2>/dev/null || true
  echo ""; echo "=== TEST OUTPUT ==="; sed -n '1,300p' "${ARTIFACT_DIR}/go-test-output.txt" 2>/dev/null || true
  echo ""; echo "=== LINT STDERR ==="; sed -n '1,300p' "${ARTIFACT_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo ""; echo "=== FILE SNIPPETS ==="
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && { echo "----- $f -----"; sed -n '1,200p' "$f"; echo; } || true; done
} >> "$PROMPT_FILE"

# -------------------------
# Step 4: call OpenRouter (Python helper for reliability)
PY_CALL="$(mktemp)"
cat > "$PY_CALL" <<'PY_EOF'
#!/usr/bin/env python3
import os,sys,time,socket,json
try:
  import requests
except Exception:
  sys.stderr.write("requests missing\n"); sys.exit(2)
API_URL="https://openrouter.ai/api/v1/chat/completions"
API_KEY=os.environ.get("OPENROUTER_API_KEY")
MODEL=os.environ.get("OPENROUTER_MODEL")
if not API_KEY or not MODEL:
  sys.stderr.write("missing OPENROUTER_API_KEY or OPENROUTER_MODEL\n"); sys.exit(2)
prompt_path=sys.argv[1]
with open(prompt_path,'r',encoding='utf-8') as fh:
  user_text=fh.read()
payload={"model":MODEL,"messages":[{"role":"system","content":"You are a precise Go patch generator."},{"role":"user","content":user_text}],"temperature":0.0,"max_tokens":32768}
host="openrouter.ai"
for i in range(6):
  try:
    socket.gethostbyname(host); break
  except Exception:
    time.sleep((i+1)*1.5)
headers={"Authorization":f"Bearer {API_KEY}","Content-Type":"application/json"}
for attempt in range(6):
  try:
    r=requests.post(API_URL, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    json.dump(r.json(), sys.stdout, ensure_ascii=False)
    sys.exit(0)
  except Exception as e:
    sys.stderr.write(f"request error {attempt+1}: {e}\n")
    time.sleep((attempt+1)*2)
sys.stderr.write("failed after retries\n"); sys.exit(3)
PY_EOF
chmod +x "$PY_CALL"

# ensure python requests available
if ! python3 -c "import requests" >/dev/null 2>&1; then
  if command -v pip3 >/dev/null 2>&1; then python3 -m pip install --upgrade requests >/dev/null 2>&1 || true; fi
fi

RESPONSE_JSON="$(mktemp)"
set +e
python3 "$PY_CALL" "$PROMPT_FILE" > "$RESPONSE_JSON" 2>> "$DIAG"
PY_EXIT=$?
set -e
cp "$RESPONSE_JSON" "$AI_RAW" || true

if [ "$PY_EXIT" -ne 0 ]; then
  echo "OpenRouter call failed (exit $PY_EXIT). See $DIAG and $AI_RAW" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# Extract AI content
EXTRACT_PY="$(mktemp)"
cat > "$EXTRACT_PY" <<'PY_EOF2'
import json,sys
try:
  obj=json.load(open(sys.argv[1],'r',encoding='utf-8'))
  choices=obj.get('choices') or []
  if choices:
    c=choices[0]
    content=c.get('message',{}).get('content') or c.get('text') or ""
  else:
    content=""
  sys.stdout.write(content or "")
except Exception as e:
  sys.stderr.write("extract error:"+str(e)); sys.exit(1)
PY_EOF2
python3 "$EXTRACT_PY" "$RESPONSE_JSON" > "$AI_RESP" 2>> "$DIAG" || true
AI_CONTENT="$(sed -n '1,20000p' "$AI_RESP" || true)"
if [ -z "${AI_CONTENT:-}" ]; then
  echo "AI returned empty content; see $AI_RAW and $DIAG" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# -------------------------
# Step 5: extract fenced patch and apply
PATCH_TMP="$(mktemp)"
EXTRACT_PATCH_PY="$(mktemp)"
cat > "$EXTRACT_PATCH_PY" <<'PY_EOF3'
import re,sys
s=open(sys.argv[1],'r',encoding='utf-8').read()
m=re.search(r'```(?:diff[^\n]*)?\n(.*?)\n```',s,re.S)
if not m:
  m=re.search(r'```\s*\n(.*?)\n```',s,re.S)
if m:
  print(m.group(1))
else:
  print("",end="")
PY_EOF3
python3 "$EXTRACT_PATCH_PY" "$AI_RESP" > "$PATCH_TMP" 2>> "$DIAG" || true

if [ ! -s "$PATCH_TMP" ]; then
  echo "No patch extracted from AI response" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

if ! git apply --check "$PATCH_TMP" > /tmp/ai_patch_check.out 2>&1; then
  echo "AI patch failed git apply --check" >> "$DIAG"
  cat /tmp/ai_patch_check.out >> "$DIAG" || true
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

git apply "$PATCH_TMP" || { echo "git apply failed" >> "$DIAG"; cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true; echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="; exit 0; }

# Validate
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
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then CHANGED_TARGETS+=("$tf"); fi
done

if [ ${#CHANGED_TARGETS[@]} -eq 0 ]; then
  echo "AI patch did not change allowed target files" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# safe branch name for AI patch
BR="$(safe_branch "ai/ai-fix" "$(date -u +%Y%m%dT%H%M%SZ)")"
git checkout -b "$BR"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
git config user.name "github-actions[bot]" || true

for f in "${CHANGED_TARGETS[@]}"; do git add -- "$f" || true; done
for f in go.mod go.sum; do
  if git status --porcelain | awk '{print $2}' | grep -Fqx "$f"; then git add -- "$f" || true; fi
done

git commit -m "[create-pull-request] automated AI-assisted fixes: ${CHANGED_TARGETS[*]}" || true
[ -n "${GH2_TOKEN:-}" ] && git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" >/dev/null 2>&1 || true
git push --set-upstream origin "$BR" || true

git diff origin/main.."${BR}" > "$PATCH_AFTER" 2>/dev/null || true
cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
cp "$VALIDATE_LOG" "${ARTIFACT_DIR}/ai-validate.log" || true

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT}"
else
  echo "pr_branch=${BR}"
fi

exit 0
 
