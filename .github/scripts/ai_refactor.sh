#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Robust AI refactor driver:
#  - base new branches on origin/main (if available)
#  - only push and emit pr_branch when remote branch actually differs from origin/main
#  - sanitize branch names
#  - perform go.mod bump only when it changes files
#  - perform safe auto-fixes (gofmt/goimports/golangci-lint --fix)
#  - call OpenRouter to produce a patch when needed
#
# Required secrets (repo): OPENROUTER_API_KEY, OPENROUTER_MODEL, GH2_TOKEN
set -euo pipefail

# Ensure we're running in bash
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi

ARTIFACT_DIR="ci-artifacts/combined"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a) ARTIFACT_DIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$ARTIFACT_DIR"

DIAG="$ARTIFACT_DIR/ai-diagnostics.txt"
AI_RAW="$ARTIFACT_DIR/ai-raw-response.json"
AI_RESP="$ARTIFACT_DIR/ai-response.txt"
VALIDATE_LOG="$ARTIFACT_DIR/ai-validate.log"
PATCH_BEFORE="$ARTIFACT_DIR/ai-diff-before.patch"
PATCH_AFTER="$ARTIFACT_DIR/ai-diff-after.patch"

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set (secret)}"
: "${OPENROUTER_MODEL:?OPENROUTER_MODEL must be set (secret)}"
: "${GH2_TOKEN:?GH2_TOKEN must be set (secret)}"

# Make git safe to operate inside runner workspace
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$(pwd)}" >/dev/null 2>&1 || true

# Ensure go exists
if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: go not found in PATH" | tee "$DIAG"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=" >> "${GITHUB_OUTPUT}"; else echo "pr_branch="; fi
  exit 1
fi

GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
mkdir -p "$GOBIN"
export PATH="$GOBIN:$PATH"

TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

# Diagnostics header
{
  echo "ai_refactor run: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "model: ${OPENROUTER_MODEL}"
} > "$DIAG"

# ---------------------------
# helpers
sanitize_ref() {
  # keep A-Za-z0-9._/- only; convert other runs to '-'
  printf '%s' "$1" | sed -E 's/[^A-Za-z0-9._\/-]+/-/g' | sed -E 's/^-+|-+$//g'
}

make_branch_name() {
  local prefix="$1"; local token="${2:-}"
  local stamp; stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if [ -n "$token" ]; then
    token="$(sanitize_ref "$token")"
    echo "${prefix}-${token}-${stamp}"
  else
    echo "${prefix}-${stamp}"
  fi
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

# returns 0 if HEAD differs from origin/main (after fetching)
head_differs_from_origin_main() {
  # ensure we have origin/main
  git fetch origin main:refs/remotes/origin/main >/dev/null 2>&1 || true
  # if no origin/main, treat HEAD as differing (new repo or shallow)
  if ! git show-ref --verify --quiet refs/remotes/origin/main; then
    return 0
  fi
  # check left/right rev-list counts: origin/main...HEAD
  local counts
  counts="$(git rev-list --left-right --count refs/remotes/origin/main...HEAD 2>/dev/null || echo "0 0")"
  local left right
  left="$(printf '%s' "$counts" | awk '{print $1}')"
  right="$(printf '%s' "$counts" | awk '{print $2}')"
  if [ "$left" = "0" ] && [ "$right" = "0" ]; then
    return 1
  fi
  return 0
}

# stage target files and commit if anything staged; returns 0 if commit made
stage_and_commit_targets() {
  local msg="$1"
  local staged=false
  for f in "${TARGET_FILES[@]}"; do
    if [ -f "$f" ]; then
      git add -- "$f" || true
      staged=true
    fi
  done
  if [ "$staged" = true ] && git diff --cached --name-only | grep -q .; then
    git commit -m "$msg" || true
    return 0
  fi
  return 1
}

# check if any target files have unstaged/untracked changes (working tree vs HEAD)
targets_have_changes() {
  if git rev-parse --verify HEAD >/dev/null 2>&1; then
    if git diff --name-only HEAD -- "${TARGET_FILES[@]}" | grep -q .; then return 0; fi
    if git ls-files --others --exclude-standard -- "${TARGET_FILES[@]}" | grep -q .; then return 0; fi
    return 1
  else
    # no HEAD - any target file present counts as change
    for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && return 0 || true; done
    return 1
  fi
}

# ---------------------------
# Start by fetching origin/main and use it as base if available
git fetch --prune origin main >/dev/null 2>&1 || true
BASE_REF="HEAD"
if git show-ref --verify --quiet refs/remotes/origin/main; then
  BASE_REF="refs/remotes/origin/main"
fi

# Save current working copy (for diagnostics)
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# ---------------------------
# STEP 0: try bumping go directive to latest patch (only if it changes files)
LATEST_GO_FULL="$(curl -fsS https://go.dev/VERSION?m=text || true)" # "go1.25.3"
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
    # tidy (best-effort)
    go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

    # if files changed vs BASE_REF then commit and push, otherwise restore
    if git diff --name-only "$BASE_REF" -- go.mod go.sum | grep -q .; then
      BR="$(make_branch_name "ai/go-bump" "$LATEST_GO")"
      BR="$(sanitize_ref "$BR")"
      if ! git check-ref-format --branch "$BR" >/dev/null 2>&1; then
        BR="ai/go-bump-$(date -u +%Y%m%dT%H%M%SZ)"
      fi
      # create branch from base ref to ensure correct ancestry
      git checkout -b "$BR" "$BASE_REF"
      git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
      git config user.name "github-actions[bot]" || true
      git add go.mod go.sum || true
      git commit -m "[create-pull-request] bump go directive to ${LATEST_GO}" || true

      # if HEAD differs from origin/main then push and emit pr branch; otherwise don't
      if head_differs_from_origin_main; then
        set_push_remote_token
        git push --set-upstream origin "$BR" || true
        emit_pr_branch "$BR"
        exit 0
      else
        echo "After commit the branch did not differ from origin/main; not creating PR." >> "$DIAG"
        # clean up branch if created
        git checkout --detach "$BASE_REF" >/dev/null 2>&1 || true
        git branch -D "$BR" >/dev/null 2>&1 || true
        # restore go.mod from backup if present
        [ -f "${ARTIFACT_DIR}/go.mod.prebump" ] && mv "${ARTIFACT_DIR}/go.mod.prebump" go.mod || true
      fi
    else
      echo "go.mod bump produced no effective change vs base; restored." >> "$DIAG"
      [ -f "${ARTIFACT_DIR}/go.mod.prebump" ] && mv "${ARTIFACT_DIR}/go.mod.prebump" go.mod || true
    fi
  else
    echo "go.mod up-to-date or missing (cur: ${CUR_GO:-none}, latest: ${LATEST_GO:-unknown})" >> "$DIAG"
  fi
fi

# ---------------------------
# STEP 1: safe auto-fixes
gofmt -s -w . || true
if ! command -v goimports >/dev/null 2>&1; then go install golang.org/x/tools/cmd/goimports@latest || true; fi
command -v goimports >/dev/null 2>&1 && goimports -w . || true

if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$GOBIN" v2.5.0 >/dev/null 2>&1 || true
fi
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --fix --timeout=10m ./... >> "${ARTIFACT_DIR}/golangci-fix.log" 2>&1 || true
go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

# If there are target changes vs BASE_REF, create a branch and commit & push if it differs from origin/main
if git diff --name-only "$BASE_REF" -- "${TARGET_FILES[@]}" | grep -q . || git ls-files --others --exclude-standard -- "${TARGET_FILES[@]}" | grep -q .; then
  BR="$(make_branch_name "ai/auto-fix")"
  BR="$(sanitize_ref "$BR")"
  git checkout -b "$BR" "$BASE_REF"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
  git config user.name "github-actions[bot]" || true
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
  if git diff --cached --name-only | grep -q .; then
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    if head_differs_from_origin_main; then
      set_push_remote_token
      git push --set-upstream origin "$BR" || true
      emit_pr_branch "$BR"
      exit 0
    else
      echo "Auto-fix commit did not differ from origin/main; cleaning up." >> "$DIAG"
      git checkout --detach "$BASE_REF" >/dev/null 2>&1 || true
      git branch -D "$BR" >/dev/null 2>&1 || true
      # continue
    fi
  else
    echo "No staged changes after safe fixes; continuing." >> "$DIAG"
    git checkout --detach "$BASE_REF" >/dev/null 2>&1 || true
  fi
fi

# ---------------------------
# STEP 2: diagnostics (build/test/lint)
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
  emit_pr_branch ""
  exit 0
fi

# ---------------------------
# STEP 3: prepare prompt
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

# ---------------------------
# STEP 4: call OpenRouter (python helper with retries)
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
# ensure 'requests' available
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

# ---------------------------
# STEP 5: extract AI content & fenced patch
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

# Validate
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

# Commit & push only if branch differs from origin/main
if git diff --name-only "$BASE_REF" -- "${TARGET_FILES[@]}" | grep -q . || git ls-files --others --exclude-standard -- "${TARGET_FILES[@]}" | grep -q .; then
  BR="$(make_branch_name "ai/ai-fix")"
  BR="$(sanitize_ref "$BR")"
  git checkout -b "$BR" "$BASE_REF"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
  git config user.name "github-actions[bot]" || true
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
  if git diff --cached --name-only | grep -q .; then
    git commit -m "[create-pull-request] automated AI-assisted fixes" || true
    # check if HEAD differs from origin/main
    if head_differs_from_origin_main; then
      set_push_remote_token
      git push --set-upstream origin "$BR" || true
      emit_pr_branch "$BR"
      exit 0
    else
      echo "AI fix commit did not differ from origin/main; not creating PR." >> "$DIAG"
      git checkout --detach "$BASE_REF" >/dev/null 2>&1 || true
      git branch -D "$BR" >/dev/null 2>&1 || true
      emit_pr_branch ""
      exit 0
    fi
  else
    echo "No staged changes after AI patch; nothing to commit." >> "$DIAG"
    emit_pr_branch ""
    exit 0
  fi
else
  echo "No target files changed after AI patch." >> "$DIAG"
  emit_pr_branch ""
  exit 0
fi
