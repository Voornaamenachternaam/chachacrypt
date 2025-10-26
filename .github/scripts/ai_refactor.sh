#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Produce PR only when allowed files actually change.
# Requires: OPENROUTER_API_KEY, GH2_TOKEN, OPENROUTER_MODEL (env or .github/ai_model.txt).
set -euo pipefail

# Re-exec under bash if not bash
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

# ---------- args ----------
ARTIFACT_DIR="ci-artifacts/combined"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a) ARTIFACT_DIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$ARTIFACT_DIR"

# ---------- artifacts ----------
DIAG="$ARTIFACT_DIR/ai-diagnostics.txt"
AI_RAW="$ARTIFACT_DIR/ai-raw-response.json"
AI_RESP="$ARTIFACT_DIR/ai-response.txt"
VALIDATE_LOG="$ARTIFACT_DIR/ai-validate.log"
PATCH_BEFORE="$ARTIFACT_DIR/ai-diff-before.patch"
PATCH_AFTER="$ARTIFACT_DIR/ai-diff-after.patch"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"

OPENROUTER_MODEL="${OPENROUTER_MODEL:-}"
if [ -z "$OPENROUTER_MODEL" ] && [ -f ".github/ai_model.txt" ]; then
  OPENROUTER_MODEL="$(sed -n '1p' .github/ai_model.txt | tr -d '[:space:]' || true)"
fi
if [ -z "$OPENROUTER_MODEL" ]; then
  echo "ERROR: OPENROUTER_MODEL not set and .github/ai_model.txt missing" | tee "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi

git config --global --add safe.directory "${GITHUB_WORKSPACE:-$(pwd)}" >/dev/null 2>&1 || true

# ensure go present
if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: go not found in PATH" | tee -a "$DIAG"
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 1
fi
GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
mkdir -p "$GOBIN"; export PATH="$GOBIN:$PATH"

# allowed target files
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

# diagnostics header
{
  echo "ai_refactor run: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "model: $OPENROUTER_MODEL"
} > "$DIAG"

# helper: safe branch name
safe_branch() {
  local prefix="$1" stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  # allowed characters: letters, numbers, dot, dash, underscore, slash; avoid spaces/colons
  echo "${prefix}-${stamp}"
}

# helper: check if any target files changed in working tree (unstaged or staged)
any_target_changed() {
  # use git diff --name-only to detect modifications compared to HEAD
  if git diff --name-only -- "${TARGET_FILES[@]}" | grep -q .; then
    return 0
  fi
  if git ls-files --others --exclude-standard -- "${TARGET_FILES[@]}" | grep -q .; then
    return 0
  fi
  return 1
}

# Save pre-change diff for diagnostics (if present)
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# -------------------------------
# STEP 0: try to bump go directive to latest patch (canonical)
# -------------------------------
LATEST_GO_FULL="$(curl -fsS https://go.dev/VERSION?m=text || true)" # e.g. "go1.25.3"
LATEST_GO=""
if [ -n "$LATEST_GO_FULL" ]; then LATEST_GO="${LATEST_GO_FULL#go}"; fi

ver_ge() {
  IFS='.' read -r -a A <<< "$1"; IFS='.' read -r -a B <<< "$2"
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
    echo "Attempting go.mod bump $CUR_GO -> $LATEST_GO" >> "$DIAG"
    cp go.mod "${ARTIFACT_DIR}/go.mod.prebump" || true
    awk -v ng="$LATEST_GO" 'BEGIN{done=0} { if (!done && $1=="go") { print "go " ng; done=1; next } print }' go.mod > go.mod.tmp && mv go.mod.tmp go.mod || true
    go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

    # check whether files actually changed
    if git diff --name-only -- go.mod go.sum | grep -q .; then
      BR="$(safe_branch "ai/go-bump-${LATEST_GO}")"
      git checkout -b "$BR"
      git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
      git config user.name "github-actions[bot]" || true
      git add go.mod go.sum || true
      git commit -m "[create-pull-request] bump go directive to ${LATEST_GO}" || true
      # set remote to push using token if provided
      if [ -n "${GH2_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
        git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" >/dev/null 2>&1 || true
      fi
      git push --set-upstream origin "$BR" || true
      echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
      exit 0
    else
      echo "go.mod write resulted in no change (already equivalent). Reverting." >> "$DIAG"
      # restore original go.mod if backup exists
      [ -f "${ARTIFACT_DIR}/go.mod.prebump" ] && mv "${ARTIFACT_DIR}/go.mod.prebump" go.mod || true
    fi
  else
    echo "No go.mod bump needed (cur: ${CUR_GO:-none}, latest: ${LATEST_GO:-unknown})" >> "$DIAG"
  fi
fi

# -------------------------------
# STEP 1: safe auto-fixes
# -------------------------------
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

# If fixes changed a target file -> commit & push branch
if any_target_changed; then
  BR="$(safe_branch "ai/auto-fix")"
  git checkout -b "$BR"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
  git config user.name "github-actions[bot]" || true
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
  # only commit if there are staged changes
  if git diff --cached --name-only | grep -q .; then
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    [ -n "${GH2_TOKEN:-}" ] && git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" >/dev/null 2>&1 || true
    git push --set-upstream origin "$BR" || true
    echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
    exit 0
  else
    echo "No staged changes after safe fixes (nothing to commit)." >> "$DIAG"
    git checkout - >/dev/null 2>&1 || true
  fi
fi

# -------------------------------
# STEP 2: collect diagnostics
# -------------------------------
go build ./... > "${ARTIFACT_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ARTIFACT_DIR}/go-test-output.txt" 2>&1 || true
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --timeout=10m --out-format json ./... > "${ARTIFACT_DIR}/golangci.runtime.json" 2> "${ARTIFACT_DIR}/golangci.runtime.stderr" || true

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

# -------------------------------
# STEP 3: prepare prompt
# -------------------------------
PROMPT_FILE="$(mktemp)"
cat > "$PROMPT_FILE" <<'PROMPT_EOF'
You are an expert Go maintainer. Produce a single unified git diff (patch) enclosed in triple backticks that fixes the build/test/lint issues below.
Only change files if necessary: chachacrypt.go, go.mod, go.sum. Keep changes minimal and safe.
PROMPT_EOF
{
  echo ""; echo "=== BUILD OUTPUT ==="; sed -n '1,300p' "${ARTIFACT_DIR}/go-build-output.txt" 2>/dev/null || true
  echo ""; echo "=== TEST OUTPUT ==="; sed -n '1,300p' "${ARTIFACT_DIR}/go-test-output.txt" 2>/dev/null || true
  echo ""; echo "=== LINT STDERR ==="; sed -n '1,300p' "${ARTIFACT_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo ""; echo "=== FILE SNIPPETS ==="
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && { echo "----- $f -----"; sed -n '1,200p' "$f"; echo; } || true; done
} >> "$PROMPT_FILE"

# -------------------------------
# STEP 4: call OpenRouter via Python helper (retries)
# -------------------------------
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
# ensure requests library available
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

# extract AI content
EXTRACT_PY="$(mktemp)"
cat > "$EXTRACT_PY" <<'PY_EX'
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
PY_EX
python3 "$EXTRACT_PY" "$RESPONSE_JSON" > "$AI_RESP" 2>> "$DIAG" || true
AI_CONTENT="$(sed -n '1,20000p' "$AI_RESP" || true)"
if [ -z "${AI_CONTENT:-}" ]; then
  echo "AI returned empty content; see $AI_RAW and $DIAG" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

# -------------------------------
# STEP 5: extract fenced patch and apply
PATCH_TMP="$(mktemp)"
EXTRACT_PATCH_PY="$(mktemp)"
cat > "$EXTRACT_PATCH_PY" <<'PY_PATCH'
import re,sys
s=open(sys.argv[1],'r',encoding='utf-8').read()
m=re.search(r'```(?:diff[^\n]*)?\n(.*?)\n```',s,re.S)
if not m:
  m=re.search(r'```\s*\n(.*?)\n```',s,re.S)
if m:
  print(m.group(1))
else:
  print("",end="")
PY_PATCH
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

# validate build/test
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

# commit only allowed files if they changed
if any_target_changed; then
  BR="$(safe_branch "ai/ai-fix")"
  git checkout -b "$BR"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
  git config user.name "github-actions[bot]" || true
  for f in "${TARGET_FILES[@]}"; do
    if git ls-files --error-unmatch "$f" >/dev/null 2>&1 || [ -f "$f" ]; then
      if git diff --name-only -- "$f" | grep -q . || git ls-files --others --exclude-standard "$f" >/dev/null 2>&1; then
        git add -- "$f" || true
      fi
    fi
  done
  # only commit if there are staged changes
  if git diff --cached --name-only | grep -q .; then
    git commit -m "[create-pull-request] automated AI-assisted fixes: $(git diff --cached --name-only | tr '\n' ' ')" || true
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
  else
    echo "AI patch produced no staged changes; nothing to commit" >> "$DIAG"
    cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
    echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
    exit 0
  fi
else
  echo "No target files changed after AI patch" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi
 
