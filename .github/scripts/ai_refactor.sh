#!/usr/bin/env bash
# .github/scripts/ai_refactor.sh
# Robust AI-assisted refactor driver with direct PR creation via GitHub REST API.
# Required repo secrets: OPENROUTER_API_KEY, OPENROUTER_MODEL, GH2_TOKEN
set -euo pipefail

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

: "${OPENROUTER_API_KEY:?OPENROUTER_API_KEY must be set}"
: "${OPENROUTER_MODEL:?OPENROUTER_MODEL must be set}"
: "${GH2_TOKEN:?GH2_TOKEN must be set}"

# ensure git operations are allowed
git config --global --add safe.directory "${GITHUB_WORKSPACE:-$(pwd)}" >/dev/null 2>&1 || true

# ensure go exists
if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: go tool not found in PATH" | tee "$DIAG"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "pr_branch=" >> "${GITHUB_OUTPUT}"; else echo "pr_branch="; fi
  exit 1
fi

GOBIN="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin"
mkdir -p "$GOBIN"
export PATH="$GOBIN:$PATH"

TARGET_FILES=( "chachacrypt.go" "go.mod" "go.sum" )

# header diagnostics
{
  echo "ai_refactor run: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "repo: ${GITHUB_REPOSITORY:-unknown}"
  echo "model: ${OPENROUTER_MODEL}"
} > "$DIAG"

# ---------------- helpers ----------------
sanitize_ref() {
  local s="$1"
  printf '%s' "$s" | sed -E 's/[^A-Za-z0-9._\/-]+/-/g' | sed -E 's/^-+|-+$//g'
}
make_branch_name() {
  local prefix="$1"; local token="${2:-}"
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  if [ -n "$token" ]; then
    token="$(sanitize_ref "$token")"
    echo "${prefix}-${token}-${ts}"
  else
    echo "${prefix}-${ts}"
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
# check whether HEAD differs from origin/main (after fetching origin/main)
head_differs_from_origin_main() {
  git fetch origin main:refs/remotes/origin/main >/dev/null 2>&1 || true
  if ! git show-ref --verify --quiet refs/remotes/origin/main; then
    return 0
  fi
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
targets_changed_vs_base() {
  local base_ref="$1"
  if git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
    git diff --name-only "$base_ref" -- "${TARGET_FILES[@]}" | grep -q . && return 0
    git ls-files --others --exclude-standard -- "${TARGET_FILES[@]}" | grep -q . && return 0
    return 1
  else
    for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && return 0 || true; done
    return 1
  fi
}

# GitHub API helpers (create PR or find existing)
gh_api() {
  # $1 method, $2 path, $3 optional data
  local method="$1"; local path="$2"; local data="${3:-}"
  local url="https://api.github.com${path}"
  if [ -n "$data" ]; then
    curl -fsSL -X "$method" -H "Authorization: token ${GH2_TOKEN}" -H "Accept: application/vnd.github+json" -H "Content-Type: application/json" -d "$data" "$url"
  else
    curl -fsSL -X "$method" -H "Authorization: token ${GH2_TOKEN}" -H "Accept: application/vnd.github+json" "$url"
  fi
}

create_or_find_pr() {
  # args: head_branch, title, body
  local head="$1"; local title="$2"; local body="$3"
  local owner repo
  owner="$(cut -d/ -f1 <<< "${GITHUB_REPOSITORY}")"
  repo="$(cut -d/ -f2 <<< "${GITHUB_REPOSITORY}")"

  # check existing PR for head (owner:head) and base=main
  local query_path="/repos/${owner}/${repo}/pulls?head=${owner}:${head}&base=main&state=open"
  local existing
  existing="$(gh_api GET "$query_path" || true)"
  if [ -n "$existing" ] && [ "$(printf '%s' "$existing" | jq -r 'length // 0')" != "0" ]; then
    local html
    html="$(printf '%s' "$existing" | jq -r '.[0].html_url')"
    echo "$html"
    return 0
  fi

  # create PR
  local payload
  payload="$(jq -n --arg t "$title" --arg h "$head" --arg b "$body" '{title:$t, head:$h, base:"main", body:$b, maintainer_can_modify:true}')"
  local resp
  resp="$(gh_api POST "/repos/${owner}/${repo}/pulls" "$payload" 2>/dev/null || true)"
  if [ -n "$resp" ]; then
    printf '%s' "$resp" | jq -r '.html_url // ""'
  else
    echo ""
  fi
}

# ---------------- main flow ----------------

# keep a pre-change diff for diagnostics
git diff -- "${TARGET_FILES[@]}" > "$PATCH_BEFORE" 2>/dev/null || true

# fetch origin/main as base if present
git fetch --prune origin main >/dev/null 2>&1 || true
BASE_REF="HEAD"
if git show-ref --verify --quiet refs/remotes/origin/main; then
  BASE_REF="refs/remotes/origin/main"
fi

# ---------------- Step 0: bump Go directive (if newer)
LATEST_GO_FULL="$(curl -fsS https://go.dev/VERSION?m=text || true)"  # e.g. go1.25.3
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

    # only create PR if changed vs base
    if targets_changed_vs_base "$BASE_REF"; then
      BR="$(make_branch_name "ai/go-bump" "$LATEST_GO")"
      BR="$(sanitize_ref "$BR")"
      if ! git check-ref-format --branch "$BR" >/dev/null 2>&1; then
        BR="ai/go-bump-$(date -u +%Y%m%dT%H%M%SZ)"
      fi
      # create branch from base for deterministic ancestry
      git checkout -b "$BR" "$BASE_REF"
      git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
      git config user.name "github-actions[bot]" || true
      git add go.mod go.sum || true
      git commit -m "[create-pull-request] bump go directive to ${LATEST_GO}" || true

      # ensure branch really differs from origin/main
      if head_differs_from_origin_main; then
        set_push_remote_token
        git push --set-upstream origin "$BR" || true
        # create PR via API
        PR_URL="$(create_or_find_pr "$BR" "chore: bump go to ${LATEST_GO}" "Automated bump of Go version to ${LATEST_GO} (AI-assisted).")" || true
        if [ -n "$PR_URL" ]; then
          echo "PR created: $PR_URL" >> "$DIAG"
          emit_pr_branch "$BR"
          exit 0
        else
          echo "Failed to create PR or found none; branch pushed." >> "$DIAG"
          emit_pr_branch "$BR"
          exit 0
        fi
      else
        echo "After commit, branch does not differ from origin/main; restoring." >> "$DIAG"
        git checkout --detach "$BASE_REF" >/dev/null 2>&1 || true
        git branch -D "$BR" >/dev/null 2>&1 || true
        [ -f "${ARTIFACT_DIR}/go.mod.prebump" ] && mv "${ARTIFACT_DIR}/go.mod.prebump" go.mod || true
      fi
    else
      echo "go.mod bump produced no change vs base; restored." >> "$DIAG"
      [ -f "${ARTIFACT_DIR}/go.mod.prebump" ] && mv "${ARTIFACT_DIR}/go.mod.prebump" go.mod || true
    fi
  else
    echo "No go.mod bump needed (cur: ${CUR_GO:-none}, latest: ${LATEST_GO:-unknown})" >> "$DIAG"
  fi
fi

# ---------------- Step 1: safe auto-fixes
gofmt -s -w . || true
if ! command -v goimports >/dev/null 2>&1; then go install golang.org/x/tools/cmd/goimports@latest || true; fi
command -v goimports >/dev/null 2>&1 && goimports -w . || true

if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$GOBIN" v2.5.0 >/dev/null 2>&1 || true
fi
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --fix --timeout=10m ./... >> "${ARTIFACT_DIR}/golangci-fix.log" 2>&1 || true
go mod tidy >> "${ARTIFACT_DIR}/go-mod-tidy.log" 2>&1 || true

# if targets changed vs base, make branch/commit and create PR if branch differs
if targets_changed_vs_base "$BASE_REF"; then
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
      PR_URL="$(create_or_find_pr "$BR" "chore: automated safe fixes" "Automated safe fixes (gofmt, goimports, golangci-lint --fix).")" || true
      if [ -n "$PR_URL" ]; then echo "PR: $PR_URL" >> "$DIAG"; fi
      emit_pr_branch "$BR"
      exit 0
    else
      echo "Auto-fix commit did not differ from origin/main; cleaning up." >> "$DIAG"
      git checkout --detach "$BASE_REF" >/dev/null 2>&1 || true
      git branch -D "$BR" >/dev/null 2>&1 || true
      # continue
    fi
  else
    echo "No staged changes after safe fixes." >> "$DIAG"
    git checkout --detach "$BASE_REF" >/dev/null 2>&1 || true
  fi
fi

# ---------------- Step 2: collect diagnostics
go build ./... > "${ARTIFACT_DIR}/go-build-output.txt" 2>&1 || true
go test ./... > "${ARTIFACT_DIR}/go-test-output.txt" 2>&1 || true
command -v golangci-lint >/dev/null 2>&1 && golangci-lint run --timeout=10m --out-format json ./... > "${ARTIFACT_DIR}/golangci.runtime.json" 2> "${ARTIFACT_DIR}/golangci.runtime.stderr" || true

NEED_AI=false
if [ -s "${ARTIFACT_DIR}/go-build-output.txt" ] || [ -s "${ARTIFACT_DIR}/go-test-output.txt" ]; then NEED_AI=true; fi
if [ -f "${ARTIFACT_DIR}/golangci.runtime.json" ] && command -v jq >/dev/null 2>&1; then
  if jq -r '.Issues[]?.Pos?.Filename // empty' "${ARTIFACT_DIR}/golangci.runtime.json" | grep -E "$(printf '%s|%s|%s' "${TARGET_FILES[0]}" "${TARGET_FILES[1]}" "${TARGET_FILES[2]}")" >/dev/null 2>&1; then NEED_AI=true; fi
fi
if [ "$NEED_AI" = false ]; then
  echo "No build/test/lint issues requiring AI." >> "$DIAG"
  emit_pr_branch ""
  exit 0
fi

# ---------------- Step 3: prepare prompt
PROMPT_FILE="$(mktemp)"
cat > "$PROMPT_FILE" <<'PROMPT_EOF'
You are an expert Go maintainer. Produce a single unified git diff (patch) enclosed in triple backticks that fixes the build/test/lint issues below.
Only modify files if necessary: chachacrypt.go, go.mod, go.sum. Keep changes minimal and safe. Do not invent features.
PROMPT_EOF
{
  echo ""; echo "=== BUILD OUTPUT ==="; sed -n '1,500p' "${ARTIFACT_DIR}/go-build-output.txt" 2>/dev/null || true
  echo ""; echo "=== TEST OUTPUT ==="; sed -n '1,500p' "${ARTIFACT_DIR}/go-test-output.txt" 2>/dev/null || true
  echo ""; echo "=== LINT STDERR ==="; sed -n '1,500p' "${ARTIFACT_DIR}/golangci.runtime.stderr" 2>/dev/null || true
  echo ""; echo "=== FILE SNIPPETS ==="
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && { echo "----- $f -----"; sed -n '1,300p' "$f"; echo; } || true; done
} >> "$PROMPT_FILE"

# ---------------- Step 4: call OpenRouter (python helper)
PY_CALL="$(mktemp)"
cat > "$PY_CALL" <<'PYPY'
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
    socket.gethostbyname(host)
    break
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
PYPY
chmod +x "$PY_CALL"
# ensure requests installed
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

# extract content
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

# ---------------- Step 5: extract fenced patch and apply
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

# Validate build/test after applying patch
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

# Commit and create PR only if changed vs base
if targets_changed_vs_base "$BASE_REF"; then
  BR="$(make_branch_name "ai/ai-fix")"
  BR="$(sanitize_ref "$BR")"
  git checkout -b "$BR" "$BASE_REF"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com" || true
  git config user.name "github-actions[bot]" || true
  for f in "${TARGET_FILES[@]}"; do [ -f "$f" ] && git add -- "$f" || true; done
  if git diff --cached --name-only | grep -q .; then
    git commit -m "[create-pull-request] automated AI-assisted fixes" || true
    if head_differs_from_origin_main; then
      set_push_remote_token
      git push --set-upstream origin "$BR" || true
      PR_URL="$(create_or_find_pr "$BR" "chore: automated AI-assisted fixes" "Automated AI-assisted fixes (build/lint/test diagnostic fixes).")" || true
      if [ -n "$PR_URL" ]; then
        echo "PR created: $PR_URL" >> "$DIAG"
      else
        echo "PR may already exist or failed to create; check diagnostics." >> "$DIAG"
      fi
      emit_pr_branch "$BR"
      exit 0
    else
      echo "AI commit did not differ from origin/main; cleaning up." >> "$DIAG"
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
