#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Drop-in robust AI refactor driver (Go projects).
# - Requires: OPENROUTER_API_KEY, GH2_TOKEN
# - Optionally: OPENROUTER_MODEL (env or .github/ai_model.txt). You said this secret exists.
set -euo pipefail

# Ensure bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi

# -------------------------
# args
ARTIFACT_DIR="ci-artifacts/combined"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts|-a) ARTIFACT_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; shift ;;
  esac
done

mkdir -p "$ARTIFACT_DIR"

# -------------------------
# init variables (avoid set -u errors)
AI_CONTENT=""
PR_BRANCH=""
TMPFILES=()
DIAG="$ARTIFACT_DIR/ai-diagnostics.txt"
AI_RAW="$ARTIFACT_DIR/ai-raw-response.json"
AI_RESP="$ARTIFACT_DIR/ai-response.txt"
PATCH_BEFORE="$ARTIFACT_DIR/ai-diff-before.patch"
PATCH_AFTER="$ARTIFACT_DIR/ai-diff-after.patch"
VALIDATE_LOG="$ARTIFACT_DIR/ai-validate.log"

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

# Keep git safe in runners
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$(pwd)}" >/dev/null 2>&1 || true

# Ensure GOBIN on PATH
if command -v go >/dev/null 2>&1; then
  GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
  mkdir -p "$GOBIN"
  export PATH="$GOBIN:$PATH"
fi

# Save before-diff
TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# diagnostics header
{
  echo "ai_refactor run: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "model: $OPENROUTER_MODEL"
} > "$DIAG"

#
# STEP 0 — Ensure go.mod 'go' directive is up-to-date to latest stable patch
#
# Query canonical latest Go version (e.g. go1.25.3)
LATEST_GO_STR="$(curl -fsS https://go.dev/VERSION?m=text || true)"
# LATEST_GO_STR expected like "go1.25.3". If empty, skip.
if [ -n "$LATEST_GO_STR" ]; then
  LATEST_GO="${LATEST_GO_STR#go}"  # e.g. "1.25.3"
else
  LATEST_GO=""
fi

# function to compare semver-ish patch versions (returns 0 if a >= b)
ver_ge() {
  # returns 0 if $1 >= $2
  IFS='.' read -r -a a <<< "$1"
  IFS='.' read -r -a b <<< "$2"
  for i in 0 1 2; do
    ai=${a[i]:-0}; bi=${b[i]:-0}
    if ((10#$ai > 10#$bi)); then return 0; fi
    if ((10#$ai < 10#$bi)); then return 1; fi
  done
  return 0
}

if [ -f "go.mod" ] && [ -n "$LATEST_GO" ]; then
  CUR_GO="$(awk '/^go /{print $2; exit}' go.mod || true)"
  if [ -n "$CUR_GO" ] && ! ver_ge "$CUR_GO" "$LATEST_GO"; then
    echo "Updating go.mod go directive: $CUR_GO -> $LATEST_GO" >> "$DIAG"
    # safe replace
    cp go.mod "${ARTIFACT_DIR}/go.mod.bak" || true
    awk -v ng="$LATEST_GO" '{
      if ($1=="go") { print "go " ng; sub(/^go[[:space:]]+.*$/,"", $0); next }
      print
    }' go.mod > go.mod.tmp && mv go.mod.tmp go.mod || true
    # Run tidy/build/test to validate. If validation passes, commit later as a single change (branch)
    go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true
    set +e
    go build ./... >> "$VALIDATE_LOG" 2>&1
    BUILD_EXIT=$?
    go test ./... >> "$VALIDATE_LOG" 2>&1
    TEST_EXIT=$?
    set -e
    if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
      # commit and push this single update and exit (no need to call AI)
      TS="$(date -u +%Y%m%d%H%M%S)"
      BR="ai/go-upgrade-${LATEST_GO}-${TS}"
      git checkout -b "$BR"
      git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
      git config user.name "github-actions[bot]" || true
      git add go.mod go.sum || true
      git commit -m "[create-pull-request] bump go version to ${LATEST_GO}" || true
      git push --set-upstream origin "$BR" || true
      echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
      exit 0
    else
      # if upgrade caused failures then restore original go.mod and continue with diagnostics (AI will be invoked)
      cp "${ARTIFACT_DIR}/go.mod.bak" go.mod || true
      echo "Upgrade to $LATEST_GO caused build/test failures; reverting go.mod and continuing to AI." >> "$DIAG"
    fi
  else
    echo "go.mod go directive is up-to-date or no go.mod present." >> "$DIAG"
  fi
fi

#
# STEP 1 — Safe automatic fixes (gofmt/goimports/golangci-lint --fix)
#
gofmt -s -w . || true
if command -v goimports >/dev/null 2>&1; then goimports -w . || true; fi
if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$GOBIN" v2.5.0 >/dev/null 2>&1 || true
fi
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --fix --timeout=10m ./... >> "${ARTIFACT_DIR}/golangci-fix.log" 2>&1 || true
go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

# If safe fixes changed allowed files -> commit & push branch and exit
CHANGED_NOW="$(git status --porcelain | awk '{print $2}' || true)"
for tf in "${TARGET_FILES[@]}"; do
  if echo "$CHANGED_NOW" | grep -Fqx "$tf"; then
    TS="$(date -u +%Y%m%d%H%M%S)"
    BR="ai/auto-fix-${TS}"
    git checkout -b "$BR"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
    git config user.name "github-actions[bot]" || true
    for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
    git commit -m "[create-pull-request] automated safe fixes (gofmt/golangci-lint --fix)" || true
    git push --set-upstream origin "$BR" || true
    echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch=${BR}"
    exit 0
  fi
done

#
# STEP 2 — Collect build/test/lint diagnostics
#
go build ./... > "${ARTIFACT_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ARTIFACT_DIR}/go-test-output.txt" 2>&1 || true
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=10m --out-format json ./... > "${ARTIFACT_DIR}/golangci.runtime.json" 2> "${ARTIFACT_DIR}/golangci.runtime.stderr" || true
fi

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

#
# STEP 3 — Prepare prompt
#
PROMPT_FILE="$(mktemp)"; TMPFILES+=( "$PROMPT_FILE" )
cat > "$PROMPT_FILE" <<'PROMPT_EOF'
You are an expert Go engineer. Produce a single unified git diff (patch) enclosed in triple backticks that fixes the build/test/lint issues below.
Only change files if necessary: chachacrypt.go, go.mod, go.sum. Keep changes minimal and safe. If updating go.mod keep changes minimal and run 'go mod tidy'.
PROMPT_EOF

{
  echo ""; echo "=== BUILD OUTPUT (truncated) ==="; sed -n '1,300p' "${ARTIFACT_DIR}/go-build-output.txt" 2>/dev/null || true
  echo ""; echo "=== TEST OUTPUT (truncated) ==="; sed -n '1,300p' "${ARTIFACT_DIR}/go-test-output.txt" 2>/dev/null || true
  echo ""; echo "=== LINT STDERR (truncated) ==="; sed -n '1,300p' "${ARTIFACT_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo ""; echo "=== FILE CONTEXT (first 300 lines) ==="
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && { echo "----- FILE: $f -----"; sed -n '1,300p' "$f"; echo; } || true; done
} >> "$PROMPT_FILE"

#
# STEP 4 — Call OpenRouter via small Python helper (robust)
#
PY_CALL="$(mktemp)"; TMPFILES+=( "$PY_CALL" )
cat > "$PY_CALL" <<'PY_CALL_EOF'
#!/usr/bin/env python3
import os,sys,time,socket,json
try:
    import requests
except Exception:
    sys.stderr.write("missing requests\n"); sys.exit(2)
API_URL="https://openrouter.ai/api/v1/chat/completions"
API_KEY=os.environ.get("OPENROUTER_API_KEY")
MODEL=os.environ.get("OPENROUTER_MODEL")
if not API_KEY or not MODEL:
    sys.stderr.write("missing API_KEY or MODEL\n"); sys.exit(2)
prompt_file=sys.argv[1]
with open(prompt_file,'r',encoding='utf-8') as fh:
    user=fh.read()
payload={"model":MODEL,"messages":[{"role":"system","content":"You are a senior Go refactoring assistant."},{"role":"user","content":user}],"temperature":0.2,"max_tokens":32768}
# DNS check (best-effort)
host="openrouter.ai"
ok=False
for i in range(6):
    try:
        socket.gethostbyname(host); ok=True; break
    except Exception:
        time.sleep((i+1)*1.5)
# POST with retries
headers={"Authorization":f"Bearer {API_KEY}","Content-Type":"application/json"}
for attempt in range(6):
    try:
        r=requests.post(API_URL,headers=headers,json=payload,timeout=120)
        r.raise_for_status()
        json.dump(r.json(),sys.stdout,ensure_ascii=False)
        sys.exit(0)
    except requests.exceptions.RequestException as e:
        sys.stderr.write(f"request error {attempt+1}: {e}\n")
        time.sleep((attempt+1)*2)
sys.stderr.write("failed after retries\n"); sys.exit(3)
PY_CALL_EOF
chmod +x "$PY_CALL"

# Ensure 'requests' available
if ! python3 -c "import requests" >/dev/null 2>&1; then
  if command -v pip3 >/dev/null 2>&1; then
    python3 -m pip install --upgrade requests >/dev/null 2>&1 || true
  fi
fi

RESPONSE_JSON="$(mktemp)"; TMPFILES+=( "$RESPONSE_JSON" )
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

# Extract content safely
EXTRACT_PY="$(mktemp)"; TMPFILES+=( "$EXTRACT_PY" )
cat > "$EXTRACT_PY" <<'EXTRACT_PY_EOF'
import json,sys
try:
    obj=json.load(open(sys.argv[1],'r',encoding='utf-8'))
    choices=obj.get("choices") or []
    if choices:
        c=choices[0]
        cont=c.get("message",{}).get("content") or c.get("text") or ""
    else:
        cont=""
    sys.stdout.write(cont or "")
except Exception as e:
    sys.stderr.write("extract error:"+str(e))
    sys.exit(1)
EXTRACT_PY_EOF
python3 "$EXTRACT_PY" "$RESPONSE_JSON" > "$AI_RESP" 2>> "$DIAG" || true
AI_CONTENT="$(sed -n '1,20000p' "$AI_RESP" || true)"
if [ -z "${AI_CONTENT:-}" ]; then
  echo "AI returned empty content; see $AI_RAW and $DIAG" >> "$DIAG"
  cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true
  echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="
  exit 0
fi

#
# STEP 5 — extract fenced patch
#
PATCH_TMP="$(mktemp)"; TMPFILES+=( "$PATCH_TMP" )
EXTRACT_PATCH_PY="$(mktemp)"; TMPFILES+=( "$EXTRACT_PATCH_PY" )
cat > "$EXTRACT_PATCH_PY" <<'EXTRACT_PATCH_PY_EOF'
import re,sys
s=open(sys.argv[1],'r',encoding='utf-8').read()
m=re.search(r'```(?:diff[^\n]*)?\n(.*?)\n```',s,re.S)
if not m:
    m=re.search(r'```\s*\n(.*?)\n```',s,re.S)
if m:
    print(m.group(1))
else:
    print("",end="")
EXTRACT_PATCH_PY_EOF
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

# Apply patch
git apply "$PATCH_TMP" || { echo "git apply failed" >> "$DIAG"; cp "$DIAG" "${ARTIFACT_DIR}/ai-diagnostics.txt" || true; echo "pr_branch=" >> "${GITHUB_OUTPUT:-/dev/null}" || echo "pr_branch="; exit 0; }

# Validate build/test after AI patch
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

# Emit pr_branch to GITHUB_OUTPUT
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "pr_branch=${BR}" >> "${GITHUB_OUTPUT}"
else
  echo "pr_branch=${BR}"
fi

exit 0
 
