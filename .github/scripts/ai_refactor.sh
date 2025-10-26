#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Safe AI refactor driver — creates PR branches only when allowed files actually change.
# Required secrets: OPENROUTER_API_KEY, OPENROUTER_MODEL, GH2_TOKEN
set -euo pipefail

# Ensure bash
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

# -------------------------
# Args
ARTIFACT_DIR="ci-artifacts/combined"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a) ARTIFACT_DIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$ARTIFACT_DIR"

# -------------------------
# Paths
DIAG="$ARTIFACT_DIR/ai-diagnostics.txt"
AI_RAW="$ARTIFACT_DIR/ai-raw-response.json"
AI_RESP="$ARTIFACT_DIR/ai-response.txt"
VALIDATE_LOG="$ARTIFACT_DIR/ai-validate.log"
PATCH_BEFORE="$ARTIFACT_DIR/ai-diff-before.patch"
PATCH_AFTER="$ARTIFACT_DIR/ai-diff-after.patch"

# -------------------------
# Required env
: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${OPENROUTER_MODEL:?OPENROUTER_MODEL must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"

# Make git safe in runner
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$(pwd)}" >/dev/null 2>&1 || true

# Ensure go exists
if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: go tool not found in PATH" | tee "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi
GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
mkdir -p "$GOBIN"
export PATH="$GOBIN:$PATH"

# Allowed files
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

# DIAG header
{
  echo "ai_refactor run: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "model: ${OPENROUTER_MODEL}"
} > "$DIAG"

# ---------- helpers ----------
sanitize_ref() {
  # Keep only allowed characters, convert others to '-'
  local s="$1"
  # Replace runs of invalid chars with '-'
  printf '%s' "$s" | sed -E 's/[^A-Za-z0-9._/-]+/-/g' | sed -E 's/^-+|-+$//g'
}

make_branch_name() {
  # prefix and optional token
  local prefix="$1"; local token="${2:-}"
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  if [ -n "$token" ]; then
    token="$(sanitize_ref "$token")"
    echo "${prefix}-${token}-${ts}"
  else
    echo "${prefix}-${ts}"
  fi
}

# Return 0 if any allowed target files differ from HEAD or are untracked (i.e., real change)
targets_changed() {
  # If repo has HEAD, compare; otherwise check file presence
  if git rev-parse --verify HEAD >/dev/null 2>&1; then
    if git diff --name-only HEAD -- "${TARGET_FILES[@]}" | grep -q .; then
      return 0
    fi
    if git ls-files --others --exclude-standard -- "${TARGET_FILES[@]}" | grep -q .; then
      return 0
    fi
    return 1
  else
    for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && return 0 || true; done
    return 1
  fi
}

stage_and_commit_targets() {
  local msg="$1"
  for f in "${TARGET_FILES[@]}"; do
    if [ -f "$f" ]; then
      git add -- "$f" || true
    fi
  done
  if git diff --cached --name-only | grep -q .; then
    git commit -m "$msg" || true
    return 0
  fi
  return 1
}

set_push_remote_token() {
  if [ -n "${GH2_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" >/dev/null 2>&1 || true
  fi
}

emit_pr_branch() {
  local br="$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "pr_branch=${br}" >> "${GITHUB_OUTPUT}"
  else
    echo "pr_branch=${br}"
  fi
}

# Save before-diff for diagnostics
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# -------------------------
# STEP 0: Try Go bump (canonical)
# -------------------------
LATEST_GO_FULL="$(curl -fsS https://go.dev/VERSION?m=text || true)"  # e.g. "go1.25.3"
LATEST_GO=""
if [ -n "$LATEST_GO_FULL" ]; then LATEST_GO="${LATEST_GO_FULL#go}"; fi

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
    echo "Attempting go.mod bump ${CUR_GO} -> ${LATEST_GO}" >> "$DIAG"
    cp go.mod "${ARTIFACT_DIR}/go.mod.prebump" || true
    awk -v ng="$LATEST_GO" 'BEGIN{done=0} { if (!done && $1=="go") { print "go " ng; done=1; next } print }' go.mod > go.mod.tmp && mv go.mod.tmp go.mod || true
    go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

    # If go.mod or go.sum actually changed vs HEAD -> create branch & push
    if git diff --name-only -- go.mod go.sum | grep -q .; then
      BR="$(make_branch_name 'ai/go-bump' "$LATEST_GO")"
      BR="$(sanitize_ref "$BR")"
      if ! git check-ref-format --branch "$BR" >/dev/null 2>&1; then
        BR="ai/go-bump-$(date -u +%Y%m%dT%H%M%SZ)"
      fi
      git checkout -b "$BR"
      git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
      git config user.name "github-actions[bot]" || true
      git add go.mod go.sum || true
      git commit -m "[create-pull-request] bump go directive to ${LATEST_GO}" || true
      set_push_remote_token
      git push --set-upstream origin "$BR" || true
      emit_pr_branch "$BR"
      exit 0
    else
      echo "go.mod bump produced no file changes; restoring original go.mod" >> "$DIAG"
      [ -f "${ARTIFACT_DIR}/go.mod.prebump" ] && mv "${ARTIFACT_DIR}/go.mod.prebump" go.mod || true
    fi
  else
    echo "No go.mod bump needed (cur: ${CUR_GO:-none}, latest: ${LATEST_GO:-unknown})" >> "$DIAG"
  fi
fi

# -------------------------
# STEP 1: safe auto-fixes
# -------------------------
gofmt -s -w . || true
if ! command -v goimports >/dev/null 2>&1; then go install golang.org/x/tools/cmd/goimports@latest || true; fi
command -v goimports >/dev/null 2>&1 && goimports -w . || true

if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$GOBIN" v2.5.0 >/dev/null 2>&1 || true
fi
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --fix --timeout=10m ./... >> "${ARTIFACT_DIR}/golangci-fix.log" 2>&1 || true
go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

# If any target files changed -> commit & push branch
if targets_changed; then
  BR="$(make_branch_name 'ai/auto-fix' "$(date -u +%Y%m%dT%H%M%SZ)")"
  BR="$(sanitize_ref "$BR")"
  git checkout -b "$BR"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
  git config user.name "github-actions[bot]" || true
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
  if git diff --cached --name-only | grep -q .; then
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    set_push_remote_token
    git push --set-upstream origin "$BR" || true
    emit_pr_branch "$BR"
    exit 0
  else
    echo "Safe fixes did not result in staged changes; continue." >> "$DIAG"
    git checkout - >/dev/null 2>&1 || true
  fi
fi

# -------------------------
# STEP 2: collect diagnostics (build/test/lint)
# -------------------------
go build ./... > "${ARTIFACT_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ARTIFACT_DIR}/go-test-output.txt" 2>&1 || true
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --timeout=10m --out-format json ./... > "${ARTIFACT_DIR}/golangci.runtime.json" 2> "${ARTIFACT_DIR}/golangci.runtime.stderr" || true

NEED_AI=false
if [ -s "${ARTIFACT_DIR}/go-build-output.txt" ] || [ -s "${ARTIFACT_DIR}/go-test-output.txt" ]; then NEED_AI=true; fi
if [ -f "${ARTIFACT_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ARTIFACT_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|%s|%s' "${TARGET_FILES[0]}" "${TARGET_FILES[1]}" "${TARGET_FILES[2]}")" >/dev/null 2>&1; then NEED_AI=true; fi
fi
if [ "$NEED_AI" = false ]; then
  echo "No build/test/lint issues needing AI." >> "$DIAG"
  emit_pr_branch ""
  exit 0
fi

# -------------------------
# STEP 3: prepare AI prompt
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
# STEP 4: call OpenRouter via python helper (retries & diagnostics)
PY_CALL="$(mktemp)"
cat > "$PY_CALL" <<'PY_PY'
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
PY_PY
chmod +x "$PY_CALL"
# ensure requests
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
  emit_pr_branch ""
  exit 0
fi

# Extract AI content
EXTRACT_PY="$(mktemp)"
cat > "$EXTRACT_PY" <<'EXTRACTPY'
import json,sys
try:
  obj=json.load(open(sys.argv[1],'r',encoding='utf-8'))
  choices=obj.get("choices") or []
  if choices:
    c=choices[0]
    content=c.get("message",{}).get("content") or c.get("text") or ""
  else:
    content=""
  sys.stdout.write(content or "")
except Exception as e:
  sys.stderr.write("extract error:"+str(e)); sys.exit(1)
EXTRACTPY
python3 "$EXTRACT_PY" "$RESPONSE_JSON" > "$AI_RESP" 2>> "$DIAG" || true
AI_CONTENT="$(sed -n '1,20000p' "$AI_RESP" || true)"
if [ -z "${AI_CONTENT:-}" ]; then
  echo "AI returned empty content; see $AI_RAW and $DIAG" >> "$DIAG"
  emit_pr_branch ""
  exit 0
fi

# -------------------------
# STEP 5: extract fenced patch
PATCH_TMP="$(mktemp)"
EXTRACT_PATCH_PY="$(mktemp)"
cat > "$EXTRACT_PATCH_PY" <<'PATCHPY'
import re,sys
s=open(sys.argv[1],'r',encoding='utf-8').read()
m=re.search(r'```(?:diff[^\n]*)?\n(.*?)\n```',s,re.S)
if not m:
  m=re.search(r'```\s*\n(.*?)\n```',s,re.S)
if m:
  print(m.group(1))
else:
  print("",end="")
PATCHPY
python3 "$EXTRACT_PATCH_PY" "$AI_RESP" > "$PATCH_TMP" 2>> "$DIAG" || true

if [ ! -s "$PATCH_TMP" ]; then
  echo "No patch extracted from AI response" >> "$DIAG"
  emit_pr_branch ""
  exit 0
fi

if ! git apply --check "$PATCH_TMP" > /tmp/ai_patch_check.out 2>&1; then
  echo "AI patch failed git apply --check" >> "$DIAG"
  cat /tmp/ai_patch_check.out >> "$DIAG" || true
  emit_pr_branch ""
  exit 0
fi

git apply "$PATCH_TMP" || { echo "git apply failed" >> "$DIAG"; emit_pr_branch ""; exit 0; }

# Validate after applying
set +e
go mod tidy >> "$VALIDATE_LOG" 2>&1 || true
go build ./... >> "$VALIDATE_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$VALIDATE_LOG" 2>&1
TEST_EXIT=$?
set -e

if [ "$BUILD_EXIT" -ne 0 ] || [ "$TEST_EXIT" -ne 0 ]; then
  echo "Validation failed after AI patch; reverting." >> "$DIAG"
  git checkout -- . || true
  cp "$VALIDATE_LOG" "${ARTIFACT_DIR}/ai-validate.log" || true
  emit_pr_branch ""
  exit 0
fi

# Commit and push only if target files changed
if targets_changed; then
  BR="$(make_branch_name 'ai/ai-fix' "$(date -u +%Y%m%dT%H%M%SZ)")"
  BR="$(sanitize_ref "$BR")"
  git checkout -b "$BR"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
  git config user.name "github-actions[bot]" || true
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
  if git diff --cached --name-only | grep -q .; then
    git commit -m "[create-pull-request] automated AI-assisted fixes" || true
    set_push_remote_token
    git push --set-upstream origin "$BR" || true
    emit_pr_branch "$BR"
    exit 0
  else
    echo "No staged changes after AI patch" >> "$DIAG"
    emit_pr_branch ""
    exit 0
  fi
else
  echo "No target files changed after AI patch" >> "$DIAG"
  emit_pr_branch ""
  exit 0
fi
