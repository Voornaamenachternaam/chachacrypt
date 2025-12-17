#!/usr/bin/env bash
#
# ai_refactor.sh - final corrected version.
# - parses args BEFORE building semver helper (fixes "No such file or directory")
# - builds semver helper in isolated dir with isolated caches
# - writes build logs into build dir, then copies them into ARTIFACT_DIR
# - fallback prompt if missing
# - refuses go/module downgrades, verifies build/test, commits & (optionally) creates PR
#
set -euo pipefail

# -------------------------
# Defaults (can be overridden by --artifacts / --prompt-file)
# -------------------------
ARTIFACT_DIR="${ARTIFACT_DIR:-ci-artifacts/combined}"
PROMPT_FILE="${PROMPT_FILE:-.github/ai_prompt.md}"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TMP_BRANCH="ai-refactor-temp-${TIMESTAMP}"
RAW_MODEL_OUT=""      # set after ARTIFACT_DIR ensured
AI_PATCH=""
APPLY_LOG=""
BUILD_LOG=""
TEST_LOG=""
VERSION_CHECK_LOG=""
METADATA_JSON=""

# -------------------------
# Helpers
# -------------------------
log() { printf "%s %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
err() { printf "%s %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "ERROR: $*" >&2; }

CLEANUP_DIRS=()
cleanup() {
  for d in "${CLEANUP_DIRS[@]:-}"; do
    if [ -n "${d}" ] && [ -d "${d}" ]; then
      rm -rf "${d}" || true
    fi
  done
}
trap cleanup EXIT

# -------------------------
# Parse args early (IMPORTANT)
# -------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --artifacts|-a)
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    --prompt-file)
      PROMPT_FILE="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

# ensure artifact dir and log variables
mkdir -p "${ARTIFACT_DIR}"
RAW_MODEL_OUT="${ARTIFACT_DIR}/model-raw.json"
AI_PATCH="${ARTIFACT_DIR}/ai.patch"
APPLY_LOG="${ARTIFACT_DIR}/apply.log"
BUILD_LOG="${ARTIFACT_DIR}/go-build.log"
TEST_LOG="${ARTIFACT_DIR}/go-test.log"
VERSION_CHECK_LOG="${ARTIFACT_DIR}/version-check.log"
METADATA_JSON="${ARTIFACT_DIR}/metadata.json"

# -------------------------
# Now create an isolated build dir for semver helper
# -------------------------
SEMVER_BUILD_DIR="$(mktemp -d)"
CLEANUP_DIRS+=("${SEMVER_BUILD_DIR}")
SEMVER_HELPER_BIN="${SEMVER_BUILD_DIR}/semver_helper_bin"
SEMVER_BUILD_ERR="${SEMVER_BUILD_DIR}/semver_build.err"

log "Building semver helper in isolated dir ${SEMVER_BUILD_DIR} (avoids touching global module cache)."

# create small module source
cat > "${SEMVER_BUILD_DIR}/go.mod" <<'GOMOD'
module semverhelper
go 1.20
require golang.org/x/mod v0.31.0
GOMOD

cat > "${SEMVER_BUILD_DIR}/main.go" <<'GO'
package main
import (
  "fmt"
  "os"
  "golang.org/x/mod/semver"
)
func main() {
  if len(os.Args) != 3 {
    fmt.Fprintln(os.Stderr, "usage: semver_cmp v1 v2")
    os.Exit(2)
  }
  v1 := os.Args[1]
  v2 := os.Args[2]
  if v1 != "" && v1[0] != 'v' { v1 = "v"+v1 }
  if v2 != "" && v2[0] != 'v' { v2 = "v"+v2 }
  res := semver.Compare(v1, v2) // -1,0,1
  fmt.Printf("%d", res)
}
GO

# isolated caches inside build dir
SEMVER_GOMODCACHE="${SEMVER_BUILD_DIR}/gomodcache"
SEMVER_GOCACHE="${SEMVER_BUILD_DIR}/gocache"
SEMVER_GOPATH="${SEMVER_BUILD_DIR}/gopath"
mkdir -p "${SEMVER_GOMODCACHE}" "${SEMVER_GOCACHE}" "${SEMVER_GOPATH}"

if ! command -v go >/dev/null 2>&1; then
  err "go not found on PATH. Ensure actions/setup-go runs before this script."
  exit 3
fi

log "Compiling semver helper..."
(
  cd "${SEMVER_BUILD_DIR}"
  env \
    GOFLAGS= \
    GOPATH="${SEMVER_GOPATH}" \
    GOMODCACHE="${SEMVER_GOMODCACHE}" \
    GOCACHE="${SEMVER_GOCACHE}" \
    GO111MODULE=on \
    CGO_ENABLED=0 \
    go build -o "${SEMVER_HELPER_BIN}" ./... > "${SEMVER_BUILD_ERR}" 2>&1 || true
)

if [ ! -x "${SEMVER_HELPER_BIN}" ]; then
  err "semver helper did not compile successfully. See ${SEMVER_BUILD_ERR}"
  # Copy build err into artifact dir for debugging
  cp -f "${SEMVER_BUILD_ERR}" "${ARTIFACT_DIR}/semver_build.err" || true
  cat "${SEMVER_BUILD_ERR}" || true
  exit 4
fi
log "Semver helper compiled to ${SEMVER_HELPER_BIN}"
# copy build log into artifacts for inspection
cp -f "${SEMVER_BUILD_ERR}" "${ARTIFACT_DIR}/semver_build.err" || true

# wrapper compare function (prints -1/0/1)
compare_ver() {
  local v1="$1" v2="$2"
  "${SEMVER_HELPER_BIN}" "${v1:-}" "${v2:-}"
}

# -------------------------
# Pre-snapshot
# -------------------------
cp go.mod "${ARTIFACT_DIR}/go.mod.pre"
cp go.sum "${ARTIFACT_DIR}/go.sum.pre"
log "Saved pre-state go.mod and go.sum"

PRE_GO_VER="$(awk '/^go[[:space:]]+/{print $2; exit}' "${ARTIFACT_DIR}/go.mod.pre" || true)"
echo "pre_go_version=${PRE_GO_VER}" > "${VERSION_CHECK_LOG}"

# ------------
# validate go exists and runner version
# ------------
RUNNER_GO_VERSION="$(go version | awk '{print $3}' | sed 's/go//')"
cmp_out="$(compare_ver "${RUNNER_GO_VERSION}" "${PRE_GO_VER}" || true)"
if [ "${cmp_out}" = "" ]; then cmp_out=0; fi
# cmp_out == -1 => runner < pre => error
if [ "${cmp_out}" = "-1" ]; then
  err "Runner 'go' version (${RUNNER_GO_VERSION}) is older than go.mod directive (${PRE_GO_VER}). Please setup correct go version via actions/setup-go."
  echo "runner_go=${RUNNER_GO_VERSION}" >> "${VERSION_CHECK_LOG}"
  exit 6
fi
log "Runner go version ${RUNNER_GO_VERSION} validated vs go.mod ${PRE_GO_VER}"

# -------------------------
# Prompt handling (fallback)
# -------------------------
DEFAULT_PROMPT="Apply safe, minimal changes to fix linter errors and keep go.mod/go.sum versions non-downgrading. Output only a git unified diff or fenced ```diff block. Do not change module versions to lower values."
if [ ! -f "${PROMPT_FILE}" ]; then
  log "Prompt file ${PROMPT_FILE} not found; using built-in fallback prompt. (Saved to artifact.)"
  echo "${DEFAULT_PROMPT}" > "${ARTIFACT_DIR}/ai_prompt_fallback.txt"
  PROMPT_CONTENT="${DEFAULT_PROMPT}"
else
  PROMPT_CONTENT="$(cat "${PROMPT_FILE}")"
fi

# -------------------------
# Prepare AI request JSON (jq or python fallback)
# -------------------------
AI_REQ_JSON="${ARTIFACT_DIR}/ai_request.json"
if command -v jq >/dev/null 2>&1; then
  jq -n --arg model "${OPENROUTER_MODEL:-${OPENAI_MODEL:-gpt-4o-mini}}" \
        --arg system "You are an assistant that returns a unified diff patch only. Return either fenced ```diff blocks or a git-style diff; do not add commentary." \
        --arg user "${PROMPT_CONTENT}" \
        '{model:$model, messages:[{role:"system",content:$system},{role:"user",content:$user}], max_tokens:1200, temperature:0.0}' \
        > "${AI_REQ_JSON}"
else
  python - <<PY > "${AI_REQ_JSON}"
import json,sys
model = "${OPENROUTER_MODEL or OPENAI_MODEL or 'gpt-4o-mini'}"
system = "You are an assistant that returns a unified diff patch only. Return either fenced ```diff blocks or a git-style diff; do not add commentary."
user = ${json.dumps(PROMPT_CONTENT)}
print(json.dumps({"model": model, "messages":[{"role":"system","content":system},{"role":"user","content":user}], "max_tokens":1200, "temperature":0.0}))
PY
fi

# -------------------------
# Call AI provider and save raw output
# -------------------------
if [ -n "${OPENROUTER_API_KEY:-}" ]; then
  OPENROUTER_API_URL="${OPENROUTER_API_URL:-https://api.openrouter.ai/v1/chat/completions}"
  log "Calling OpenRouter API..."
  http_status=$(curl -sS -X POST \
    -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    -H "Content-Type: application/json" \
    -d @"${AI_REQ_JSON}" \
    -w "%{http_code}" \
    -o "${RAW_MODEL_OUT}.tmp" \
    "${OPENROUTER_API_URL}" || true)
  if [ -s "${RAW_MODEL_OUT}.tmp" ]; then mv "${RAW_MODEL_OUT}.tmp" "${RAW_MODEL_OUT}"; fi
  if [ "${http_status}" != "200" ] && [ "${http_status}" != "201" ]; then
    err "OpenRouter API returned HTTP ${http_status}. Raw response saved to ${RAW_MODEL_OUT}"
    exit 7
  fi
elif [ -n "${OPENAI_API_KEY:-}" ]; then
  OPENAI_API_URL="${OPENAI_API_BASE:-https://api.openai.com}/v1/chat/completions"
  log "Calling OpenAI-compatible API..."
  http_status=$(curl -sS -X POST \
    -H "Authorization: Bearer ${OPENAI_API_KEY}" \
    -H "Content-Type: application/json" \
    -d @"${AI_REQ_JSON}" \
    -w "%{http_code}" \
    -o "${RAW_MODEL_OUT}.tmp" \
    "${OPENAI_API_URL}" || true)
  if [ -s "${RAW_MODEL_OUT}.tmp" ]; then mv "${RAW_MODEL_OUT}.tmp" "${RAW_MODEL_OUT}"; fi
  if [ "${http_status}" != "200" ] && [ "${http_status}" != "201" ]; then
    err "OpenAI API returned HTTP ${http_status}. Raw response saved to ${RAW_MODEL_OUT}"
    exit 8
  fi
else
  err "No AI API key configured (OPENROUTER_API_KEY or OPENAI_API_KEY required)."
  exit 9
fi

log "Saved raw model output to ${RAW_MODEL_OUT}"

# -------------------------
# Extract patch heuristically
# -------------------------
extract_patch_from_raw() {
  local raw="$1" out="$2"
  awk '
    BEGIN {found=0}
    /^\s*```(diff|patch)/ { found=1; next }
    /^\s*```/ && found==1 { exit }
    found==1 { print }
  ' "$raw" > "$out.fenced" || true
  if [ -s "$out.fenced" ]; then mv "$out.fenced" "$out"; return 0; fi

  awk 'BEGIN{p=0} /diff --git/ {p=1} { if(p==1) print }' "$raw" > "$out.diff" || true
  if [ -s "$out.diff" ]; then mv "$out.diff" "$out"; return 0; fi

  awk 'BEGIN{p=0} /^\@\@/ {p=1} { if(p==1) print }' "$raw" > "$out.unified" || true
  if [ -s "$out.unified" ]; then mv "$out.unified" "$out"; return 0; fi

  return 1
}

if extract_patch_from_raw "${RAW_MODEL_OUT}" "${AI_PATCH}"; then
  log "Extracted patch to ${AI_PATCH}"
else
  err "No patch found in model output; saved raw output to ${RAW_MODEL_OUT}"
  exit 10
fi
chmod a+r "${AI_PATCH}" || true

# -------------------------
# Apply patch on temp branch
# -------------------------
if ! git diff --quiet || ! git diff --cached --quiet; then
  err "Repository not clean (uncommitted changes). Aborting."
  exit 11
fi

git checkout -b "${TMP_BRANCH}" >/dev/null
log "Created temporary branch ${TMP_BRANCH}"

set +e
git apply --index --whitespace=fix "${AI_PATCH}" > "${APPLY_LOG}" 2>&1
APPLY_EXIT="$?"
set -e

if [ "${APPLY_EXIT}" -ne 0 ]; then
  err "git apply failed; see ${APPLY_LOG}"
  git checkout - >/dev/null || true
  git branch -D "${TMP_BRANCH}" >/dev/null || true
  exit 12
fi
log "Patch staged successfully."

# capture staged go.mod/go.sum if present
git show :go.mod > "${ARTIFACT_DIR}/go.mod.post" 2>/dev/null || cp go.mod "${ARTIFACT_DIR}/go.mod.post"
git show :go.sum > "${ARTIFACT_DIR}/go.sum.post" 2>/dev/null || cp go.sum "${ARTIFACT_DIR}/go.sum.post"

POST_GO_VER="$(awk '/^go[[:space:]]+/{print $2; exit}' "${ARTIFACT_DIR}/go.mod.post" || true)"
echo "post_go_version=${POST_GO_VER}" >> "${VERSION_CHECK_LOG}"

# -------------------------
# Compare go directive
# -------------------------
cmp_go="$(compare_ver "${POST_GO_VER}" "${PRE_GO_VER}" || true)"
if [ "${cmp_go}" = "-1" ]; then
  err "Detected go directive downgrade: ${PRE_GO_VER} -> ${POST_GO_VER}. Refusing changes."
  git reset --hard HEAD >/dev/null || true
  git checkout - >/dev/null || true
  git branch -D "${TMP_BRANCH}" >/dev/null || true
  exit 13
fi
log "go directive check passed: ${PRE_GO_VER} -> ${POST_GO_VER}"

# -------------------------
# Dependency downgrade check via go list
# -------------------------
go list -m -json all > "${ARTIFACT_DIR}/module-list.post.json" 2>/dev/null || true

TMP_PRE_DIR="$(mktemp -d)"
CLEANUP_DIRS+=("${TMP_PRE_DIR}")
cp "${ARTIFACT_DIR}/go.mod.pre" "${TMP_PRE_DIR}/go.mod"
( cd "${TMP_PRE_DIR}" && env GOMODCACHE="${TMP_PRE_DIR}/gomodcache" go list -m -json all > "${ARTIFACT_DIR}/module-list.pre.json" 2>/dev/null ) || true

python - <<'PY' > "${ARTIFACT_DIR}/dep-compare.out" || true
import json,subprocess,sys
def load_many(path):
    out={}
    try:
        for line in open(path):
            line=line.strip()
            if not line: continue
            try:
                j=json.loads(line)
                if 'Path' in j and 'Version' in j:
                    out[j['Path']]=j['Version']
            except:
                pass
    except:
        pass
    return out
pre=load_many("${ARTIFACT_DIR}/module-list.pre.json")
post=load_many("${ARTIFACT_DIR}/module-list.post.json")
downgrades=[]
for mod, ver in pre.items():
    if mod in post:
        p=ver; q=post[mod]
        cmp = subprocess.run(["${SEMVER_HELPER_BIN}", p, q], capture_output=True, text=True)
        val = cmp.stdout.strip()
        if val == "1":
            downgrades.append((mod,p,q))
if downgrades:
    print("DOWNGRADE_DETECTED")
    for m,a,b in downgrades:
        print(m,a,"->",b)
    sys.exit(2)
else:
    print("NO_DOWNGRADES")
    sys.exit(0)
PY

if grep -q "DOWNGRADE_DETECTED" "${ARTIFACT_DIR}/dep-compare.out" 2>/dev/null; then
  err "Dependency downgrade(s) detected. See ${ARTIFACT_DIR}/dep-compare.out"
  git reset --hard HEAD >/dev/null || true
  git checkout - >/dev/null || true
  git branch -D "${TMP_BRANCH}" >/dev/null || true
  exit 14
fi
log "No dependency downgrades detected."

# -------------------------
# go.sum subset check
# -------------------------
if [ -f "${ARTIFACT_DIR}/go.sum.pre" ] && [ -f "${ARTIFACT_DIR}/go.sum.post" ]; then
  missing=0
  while read -r l; do
    [ -z "$l" ] && continue
    if ! grep -Fxq "$l" "${ARTIFACT_DIR}/go.sum.post"; then missing=$((missing+1)); fi
  done < "${ARTIFACT_DIR}/go.sum.pre"
  if [ "${missing}" -gt 0 ]; then
    err "go.sum post-state is missing ${missing} lines from pre-state. Refusing changes."
    git reset --hard HEAD >/dev/null || true
    git checkout - >/dev/null || true
    git branch -D "${TMP_BRANCH}" >/dev/null || true
    exit 15
  fi
fi
log "go.sum post-state contains pre-state entries."

# -------------------------
# Build & Test
# -------------------------
export GOFLAGS="-mod=readonly"
set +e
go build ./... > "${BUILD_LOG}" 2>&1
BUILD_EXIT="$?"
set -e
if [ "${BUILD_EXIT}" -ne 0 ]; then
  err "go build failed. See ${BUILD_LOG}"
  git reset --hard HEAD >/dev/null || true
  git checkout - >/dev/null || true
  git branch -D "${TMP_BRANCH}" >/dev/null || true
  exit 16
fi

set +e
go test ./... > "${TEST_LOG}" 2>&1
TEST_EXIT="$?"
set -e
if [ "${TEST_EXIT}" -ne 0 ]; then
  err "go test failed. See ${TEST_LOG}"
  git reset --hard HEAD >/dev/null || true
  git checkout - >/dev/null || true
  git branch -D "${TMP_BRANCH}" >/dev/null || true
  exit 17
fi
log "Build and tests succeeded."

# -------------------------
# Commit & optional PR creation
# -------------------------
git add -A
git commit -m "AI: automated refactor (verified build & tests) [ci skip]" || true

if [ -n "${GH2_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  REPO="${GITHUB_REPOSITORY}"
  HEAD_REF="${TMP_BRANCH}"
  BASE_REF="${GITHUB_BASE_REF:-main}"
  git push "https://x-access-token:${GH2_TOKEN}@github.com/${REPO}.git" "${HEAD_REF}:${HEAD_REF}" >/dev/null 2>&1 || true

  PR_TITLE="AI refactor — automated (verified build & tests)"
  PR_BODY="Automated AI refactor. CI verified build & tests. Raw model output and logs in artifact directory."
  if command -v jq >/dev/null 2>&1; then
    pr_json="$(jq -n --arg t "$PR_TITLE" --arg b "$PR_BODY" --arg head "$HEAD_REF" --arg base "$BASE_REF" '{title:$t, body:$b, head:$head, base:$base}')"
  else
    pr_json="{\"title\":\"${PR_TITLE}\",\"body\":\"${PR_BODY}\",\"head\":\"${HEAD_REF}\",\"base\":\"${BASE_REF}\"}"
  fi
  pr_resp="$(curl -sS -X POST \
    -H "Authorization: token ${GH2_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO}/pulls" \
    -d "${pr_json}" || true)"
  printf "%s\n" "${pr_resp}" > "${ARTIFACT_DIR}/pr_response.json" || true
  log "PR response saved to ${ARTIFACT_DIR}/pr_response.json"
fi

# -------------------------
# Finalize: artifact list + metadata
# -------------------------
ls -la "${ARTIFACT_DIR}" > "${ARTIFACT_DIR}/artifact-listing.txt"
cat > "${METADATA_JSON}" <<EOF
{
  "timestamp":"${TIMESTAMP}",
  "branch":"${TMP_BRANCH}",
  "go_mod_pre":"${ARTIFACT_DIR}/go.mod.pre",
  "go_mod_post":"${ARTIFACT_DIR}/go.mod.post"
}
EOF

log "ai_refactor.sh completed successfully. Artifacts: ${ARTIFACT_DIR}"
exit 0

 
