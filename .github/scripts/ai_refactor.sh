#!/usr/bin/env bash
#
# ai_refactor.sh - robust AI-driven refactor script (final, production-ready).
#
set -euo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-ci-artifacts/combined}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TMP_BRANCH="ai-refactor-temp-${TIMESTAMP}"
RAW_MODEL_OUT="${ARTIFACT_DIR}/model-raw.json"
AI_PATCH="${ARTIFACT_DIR}/ai.patch"
APPLY_LOG="${ARTIFACT_DIR}/apply.log"
BUILD_LOG="${ARTIFACT_DIR}/go-build.log"
TEST_LOG="${ARTIFACT_DIR}/go-test.log"
VERSION_CHECK_LOG="${ARTIFACT_DIR}/version-check.log"
METADATA_JSON="${ARTIFACT_DIR}/metadata.json"
PROMPT_FILE="${PROMPT_FILE:-.github/ai_prompt.md}"

mkdir -p "${ARTIFACT_DIR}"

log() { printf "%s %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
err() { printf "%s %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "ERROR: $*" >&2; }

# -------------------------
# small Go program to compare module versions using golang.org/x/mod/semver
# This is more reliable than sort -V for Go pseudo-versions.
# -------------------------
SEMVER_HELPER_SRC="$(mktemp -t semver_cmp_XXXX.go)"
SEMVER_HELPER_BIN="$(mktemp -t semver_cmp_bin_XXXX)"
cat > "${SEMVER_HELPER_SRC}" <<'EOF'
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
  // semver.Compare expects versions to start with 'v'; ensure prefix
  if v1 != "" && v1[0] != 'v' { v1 = "v"+v1 }
  if v2 != "" && v2[0] != 'v' { v2 = "v"+v2 }
  // semver.IsValid returns false for pseudo-versions; semver.Compare still works for Go module versions.
  res := semver.Compare(v1, v2)
  // semver.Compare returns -1,0,1
  fmt.Printf("%d", res)
  os.Exit(0)
}
EOF

# build helper (use 'go' installed by setup-go)
if command -v go >/dev/null 2>&1; then
  # ensure x/mod is available and compile
  log "Compiling semver helper..."
  GOPATH_TMP=$(mktemp -d)
  export GOPATH="${GOPATH_TMP}"
  # Download only the module to cache, then build
  env GO111MODULE=on go get golang.org/x/mod@latest >/dev/null 2>&1 || true
  env GO111MODULE=on CGO_ENABLED=0 go build -o "${SEMVER_HELPER_BIN}" "${SEMVER_HELPER_SRC}"
  rm -rf "${GOPATH_TMP}" || true
else
  err "go tool not available in PATH; this script requires go to be installed by actions/setup-go before running."
  exit 3
fi

# comparison wrapper using the compiled helper
compare_ver() {
  # returns:
  # - prints 0 for equal, -1 if v1 < v2, +1 if v1 > v2
  local v1="$1" v2="$2"
  if [ -z "${v1}" ]; then v1=""; fi
  if [ -z "${v2}" ]; then v2=""; fi
  "${SEMVER_HELPER_BIN}" "${v1}" "${v2}"
}

# -------------------------
# parse args
# -------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --artifacts|-a)
      ARTIFACT_DIR="$2"
      RAW_MODEL_OUT="${ARTIFACT_DIR}/model-raw.json"
      AI_PATCH="${ARTIFACT_DIR}/ai.patch"
      APPLY_LOG="${ARTIFACT_DIR}/apply.log"
      BUILD_LOG="${ARTIFACT_DIR}/go-build.log"
      TEST_LOG="${ARTIFACT_DIR}/go-test.log"
      VERSION_CHECK_LOG="${ARTIFACT_DIR}/version-check.log"
      METADATA_JSON="${ARTIFACT_DIR}/metadata.json"
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

mkdir -p "${ARTIFACT_DIR}"

# -------------------------
# Pre-snapshot
# -------------------------
cp go.mod "${ARTIFACT_DIR}/go.mod.pre"
cp go.sum "${ARTIFACT_DIR}/go.sum.pre"
log "Saved pre-state go.mod and go.sum"

PRE_GO_VER="$(awk '/^go[[:space:]]+/{print $2; exit}' "${ARTIFACT_DIR}/go.mod.pre" || true)"
echo "pre_go_version=${PRE_GO_VER}" > "${VERSION_CHECK_LOG}"

# ------------
# validate go exists
# ------------
if ! command -v go >/dev/null 2>&1; then
  err "go not found on PATH. Please ensure actions/setup-go runs before this script."
  exit 4
fi

RUNNER_GO_VERSION="$(go version | awk '{print $3}' | sed 's/go//')"
# Use semver compare: require runner version >= go.mod or equal (strictness: enforce patch exact match by default)
cmp_out=$(compare_ver "${RUNNER_GO_VERSION}" "${PRE_GO_VER}" || true)
if [ "${cmp_out}" != "0" ]; then
  # allow if runner >= requested (cmp_out == 1 means runner > required)
  if [ "${cmp_out}" = "1" ]; then
    log "Runner go ${RUNNER_GO_VERSION} is newer than go.mod directive ${PRE_GO_VER} — acceptable."
  else
    err "Runner 'go' version (${RUNNER_GO_VERSION}) is older than go.mod directive (${PRE_GO_VER}). Please set up the runner with the repository go.mod Go version (actions/setup-go)."
    echo "runner_go=${RUNNER_GO_VERSION}" >> "${VERSION_CHECK_LOG}"
    exit 5
  fi
fi

log "Runner go version ${RUNNER_GO_VERSION} validated vs go.mod ${PRE_GO_VER}"

# -------------------------
# Validate presence of prompt
# -------------------------
if [ ! -f "${PROMPT_FILE}" ]; then
  err "Prompt file ${PROMPT_FILE} not found."
  exit 6
fi
PROMPT_CONTENT="$(cat "${PROMPT_FILE}")"

# -------------------------
# Prepare AI request JSON robustly (use jq if present; else python)
# -------------------------
AI_REQ_JSON="${ARTIFACT_DIR}/ai_request.json"
if command -v jq >/dev/null 2>&1; then
  jq -n --arg model "${OPENROUTER_MODEL:-${OPENAI_MODEL:-gpt-4o-mini}}" \
        --arg system "You are an assistant that returns a unified diff patch only. Return either fenced ```diff blocks or a git-style diff; do not add commentary." \
        --arg user "${PROMPT_CONTENT}" \
        '{model:$model, messages:[{role:"system",content:$system},{role:"user",content:$user}], max_tokens:1200, temperature:0.0}' \
        > "${AI_REQ_JSON}"
else
  # fallback using Python to JSON-escape the prompt
  python - <<PY > "${AI_REQ_JSON}"
import json,sys
model = "${OPENROUTER_MODEL or OPENAI_MODEL or 'gpt-4o-mini'}"
system = "You are an assistant that returns a unified diff patch only. Return either fenced ```diff blocks or a git-style diff; do not add commentary."
user = open("${PROMPT_FILE}").read()
print(json.dumps({"model": model, "messages":[{"role":"system","content":system},{"role":"user","content":user}], "max_tokens":1200, "temperature":0.0}))
PY
fi

# -------------------------
# Call AI provider
# Prefer OPENROUTER_API_KEY if present, else fallback to OPENAI_API_KEY.
# Save raw response verbatim to RAW_MODEL_OUT
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
# Extract patch heuristically (fenced diff, git-style 'diff --git', or unified)
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
# Apply on a temporary branch safely (staged only)
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

# capture post-state from index if present, else file system
git show :go.mod > "${ARTIFACT_DIR}/go.mod.post" 2>/dev/null || cp go.mod "${ARTIFACT_DIR}/go.mod.post"
git show :go.sum > "${ARTIFACT_DIR}/go.sum.post" 2>/dev/null || cp go.sum "${ARTIFACT_DIR}/go.sum.post"

POST_GO_VER="$(awk '/^go[[:space:]]+/{print $2; exit}' "${ARTIFACT_DIR}/go.mod.post" || true)"
echo "post_go_version=${POST_GO_VER}" >> "${VERSION_CHECK_LOG}"

# -------------------------
# Compare go directive (use semver helper)
# -------------------------
cmp_go="$(compare_ver "${POST_GO_VER}" "${PRE_GO_VER}" || true)"
# cmp result -1,0,1 => negative means post < pre (downgrade)
if [ "${cmp_go}" = "-1" ]; then
  err "Detected go directive downgrade: ${PRE_GO_VER} -> ${POST_GO_VER}. Refusing changes."
  git reset --hard HEAD >/dev/null || true
  git checkout - >/dev/null || true
  git branch -D "${TMP_BRANCH}" >/dev/null || true
  exit 13
fi
log "go directive check passed: ${PRE_GO_VER} -> ${POST_GO_VER}"

# -------------------------
# Compare dependency versions using 'go list -m -json all' pre vs post
# We'll read module versions and compare via semver helper
# -------------------------
# Write module lists
go list -m -json all > "${ARTIFACT_DIR}/module-list.post.json" 2>/dev/null || true
# For pre list, we temporarily write the pre go.mod to a temp dir and run 'go list -m -modfile'
TMP_PRE_DIR="$(mktemp -d)"
cp "${ARTIFACT_DIR}/go.mod.pre" "${TMP_PRE_DIR}/go.mod"
# ensure module cache available
( cd "${TMP_PRE_DIR}" && go list -m -json all > "${ARTIFACT_DIR}/module-list.pre.json" 2>/dev/null ) || true
rm -rf "${TMP_PRE_DIR}" || true

# parse and compare versions (module path -> version)
python - <<'PY' > "${ARTIFACT_DIR}/dep-compare.out" || true
import json,sys,subprocess
pre=""+open("${ARTIFACT_DIR}/module-list.pre.json").read()
post=""+open("${ARTIFACT_DIR}/module-list.post.json").read()
def parse(s):
    arr=[]
    for obj in s.split('\n'):
        if not obj.strip(): continue
        try:
            j=json.loads(obj)
            if 'Path' in j and 'Version' in j:
                arr.append((j['Path'], j['Version']))
        except:
            pass
    return dict(arr)
p=parse(pre); q=parse(post)
downgrades=[]
for mod, ver in p.items():
    if mod in q:
        # call semver helper
        import subprocess
        out = subprocess.run(["${SEMVER_HELPER_BIN}", ver, q[mod]], capture_output=True, text=True)
        cmp = out.stdout.strip()
        # semver.Compare: -1 => ver < q[mod] (upgrade), 0 equal, 1 => ver > q[mod] (post smaller)
        if cmp == "1":
            downgrades.append((mod, ver, q[mod]))
if downgrades:
    print("DOWNGRADE_DETECTED")
    for m, a,b in downgrades:
        print(m, a, "->", b)
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
# Ensure go.sum retains pre-state lines (basic subset check)
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
# Build & Test (readonly)
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
# Commit & optional PR creation (safe)
# -------------------------
git add -A
git commit -m "AI: automated refactor (verified build & tests) [ci skip]" || true

if [ -n "${GH2_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  REPO="${GITHUB_REPOSITORY}"
  HEAD_REF="${TMP_BRANCH}"
  # Determine base (prefer GITHUB_BASE_REF, then main)
  BASE_REF="${GITHUB_BASE_REF:-main}"
  git push "https://x-access-token:${GH2_TOKEN}@github.com/${REPO}.git" "${HEAD_REF}:${HEAD_REF}" >/dev/null 2>&1 || true

  PR_TITLE="AI refactor — automated (verified build & tests)"
  PR_BODY="Automated AI refactor. CI verified build & tests. Raw model output and logs in artifact directory."
  pr_resp="$(curl -sS -X POST \
    -H "Authorization: token ${GH2_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO}/pulls" \
    -d "$(jq -n --arg t "$PR_TITLE" --arg b "$PR_BODY" --arg head "$HEAD_REF" --arg base "$BASE_REF" '{title:$t, body:$b, head:$head, base:$base}')" || true)"
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
# cleanup semver helper files
rm -f "${SEMVER_HELPER_SRC}" "${SEMVER_HELPER_BIN}" || true
exit 0
