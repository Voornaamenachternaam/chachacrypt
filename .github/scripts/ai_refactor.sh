#!/usr/bin/env bash
# /.github/scripts/ai_refactor.sh
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-}"
GIT_USER_NAME="${GIT_USER_NAME:-github-actions[bot]}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-github-actions[bot]@users.noreply.github.com}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
GH2_TOKEN="${GH2_TOKEN:-}"
MAX_ITER="${MAX_ITER:-5}"
BRANCH_PREFIX="ai/dep-updates"
TIMESTAMP="$(date +%s)"
BRANCH="${BRANCH_PREFIX}-${TIMESTAMP}"
GIT_PUSH_REMOTE="${GIT_PUSH_REMOTE:-origin}"
MODEL="qwen/qwen3-coder:free"
OPENROUTER_ENDPOINT="${OPENROUTER_ENDPOINT:-https://api.openrouter.ai/v1/chat/completions}"

function set_branch_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "branch=${BRANCH}" >> "$GITHUB_OUTPUT"
  else
    echo "::set-output name=branch::${BRANCH}" || true
  fi
}

function finish_success() {
  set_branch_output || true
  exit 0
}
trap 'finish_success' EXIT

if [ -z "$GH2_TOKEN" ]; then
  echo "GH2_TOKEN not provided; will not push or create PRs."
fi

if [ -z "$OPENROUTER_API_KEY" ]; then
  echo "OPENROUTER_API_KEY not provided; AI fixes will be skipped."
fi

git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

git fetch --all --prune

git checkout -b "$BRANCH"

# Update modules to latest (including majors), bump go directive
GOFLAGS=-mod=mod go get -u ./... || true
GOFLAGS=-mod=mod go get go@latest || true
go mod tidy

# Define allowed files for PR (only these files may be committed)
ALLOWED_FILES=( "go.mod" "go.sum" "chachacrypt.go" )

# Create a diff (before) limited to allowed files
git diff -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true

# Determine which allowed files have changes
CHANGED_ALLOWED=()
for f in "${ALLOWED_FILES[@]}"; do
  if git diff --quiet -- "$f" 2>/dev/null; then
    :
  else
    # file has unstaged changes
    CHANGED_ALLOWED+=( "$f" )
  fi
done

if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  # Try safe automatic linter fixes (do not stage anything automatically)
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=5m ./... || true
  fi
  # Re-check allowed files for changes after fixes
  CHANGED_ALLOWED=()
  for f in "${ALLOWED_FILES[@]}"; do
    if git diff --quiet -- "$f" 2>/dev/null; then
      :
    else
      CHANGED_ALLOWED+=( "$f" )
    fi
  done
fi

if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  BRANCH=""
  exit 0
fi

# Stage only allowed files that changed and commit
git add "${CHANGED_ALLOWED[@]}"
git commit -m "chore: update Go modules and go directive (automated)" || true

# Save post-update diff limited to allowed files
git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Build & test; capture logs (do NOT stage logs)
set +e
go build ./... > ai-build.log 2>&1
BUILD_EXIT=$?
go test ./... >> ai-build.log 2>&1
TEST_EXIT=$?
set -e

# Lint outputs (do NOT stage)
golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null || true
staticcheck ./... > ai-staticcheck.txt 2>/dev/null || true || true

# If build & tests passed, push branch with only allowed-file commits
if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
  if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
    git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH"
    set_branch_output
  else
    echo "Build/test passed but GH2_TOKEN/GITHUB_REPOSITORY not available; local branch created: $BRANCH"
    set_branch_output
  fi
  exit 0
fi

# Prepare diagnostics for AI
DIAGNOSTIC_SUMMARY="ai-diagnostics.txt"
echo "=== Build output ===" > "$DIAGNOSTIC_SUMMARY"
cat ai-build.log >> "$DIAGNOSTIC_SUMMARY" || true
echo "" >> "$DIAGNOSTIC_SUMMARY"
echo "=== golangci-lint output ===" >> "$DIAGNOSTIC_SUMMARY"
cat ai-lint.json >> "$DIAGNOSTIC_SUMMARY" || true
echo "" >> "$DIAGNOSTIC_SUMMARY"
echo "=== staticcheck output ===" >> "$DIAGNOSTIC_SUMMARY"
cat ai-staticcheck.txt >> "$DIAGNOSTIC_SUMMARY" || true

# Limit large files for prompt
truncate_limit() {
  local file="$1"
  local max_lines="$2"
  if [ -f "$file" ]; then
    local lines
    lines=$(wc -l < "$file" || echo 0)
    if [ "$lines" -gt "$max_lines" ]; then
      head -n "$max_lines" "$file" > "${file}.truncated"
      mv "${file}.truncated" "$file"
    fi
  fi
}

truncate_limit ai-diff-after.patch 4000
truncate_limit "$DIAGNOSTIC_SUMMARY" 4000

# Prepare system prompt instructing AI to only modify allowed files
read -r -d '' SYSTEM_PROMPT <<'SYS' || true
You are qwen3-coder, an expert Go engineer. You will be given:
- a git patch (ai-diff-after.patch) representing recent updates to go.mod/go.sum/chachacrypt.go
- build/test failure logs and linter outputs.

IMPORTANT CONSTRAINT: You must ONLY propose edits to these files if necessary: go.mod, go.sum, chachacrypt.go. Do not modify or create any other files. The pull request created by this automation must contain changes only to those three files.

Your job:
1) Analyze the diagnostics and the provided patch.
2) If possible, produce a single unified diff that modifies only go.mod, go.sum, and/or chachacrypt.go to fix build/test/lint failures and restore compatibility with the updated dependencies and updated Go toolchain.
3) Output exactly one unified patch in "git apply" format and nothing else. If no fix is possible within these file restrictions, output exactly the single line: NO_PATCH_POSSIBLE
4) Keep changes minimal, prefer small targeted edits, and do not change behavior unnecessarily.
SYS

# Read patch and diagnostics for payload
PATCH_CONTENT=$(sed -n '1,400000p' ai-diff-after.patch | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
DIAG_CONTENT=$(sed -n '1,400000p' "$DIAGNOSTIC_SUMMARY" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')

ITER=0
APPLIED_ANY=false

if [ -n "$OPENROUTER_API_KEY" ]; then
  while [ "$ITER" -lt "$MAX_ITER" ]; do
    ITER=$((ITER+1))
    echo "AI iteration $ITER / $MAX_ITER"

    read -r -d '' PAYLOAD <<EOF || true
{
  "model": "${MODEL}",
  "messages": [
    {"role":"system","content":"${SYSTEM_PROMPT}"},
    {"role":"user","content":"Patch (ai-diff-after.patch):\n\n${PATCH_CONTENT}\n\nDiagnostics:\n\n${DIAG_CONTENT}\n\nPlease produce a single unified patch that modifies only go.mod, go.sum and/or chachacrypt.go. If not possible, reply with exactly: NO_PATCH_POSSIBLE"}
  ],
  "temperature": 0.0,
  "max_tokens": 32768
}
EOF

    RESPONSE_FILE="ai-response-${ITER}.json"
    curl -sS -X POST "$OPENROUTER_ENDPOINT" \
      -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" \
      -o "$RESPONSE_FILE" || true

    PATCH_TEXT=""
    if command -v jq >/dev/null 2>&1; then
      PATCH_TEXT=$(jq -r '.choices[0].message.content // .choices[0].text // ""' "$RESPONSE_FILE" 2>/dev/null || true)
      if [ -z "$PATCH_TEXT" ] || [ "$PATCH_TEXT" = "null" ]; then
        PATCH_TEXT=$(jq -r '.output[0].content[0].text // ""' "$RESPONSE_FILE" 2>/dev/null || true)
      fi
    else
      PATCH_TEXT=$(sed -n '1,200000p' "$RESPONSE_FILE" || true)
    fi

    echo "$PATCH_TEXT" > "ai-fix-${ITER}.log"

    if echo "$PATCH_TEXT" | tr -d '\r' | grep -q '^NO_PATCH_POSSIBLE$'; then
      echo "AI responded NO_PATCH_POSSIBLE"
      break
    fi

    printf "%s\n" "$PATCH_TEXT" > "ai-fix-${ITER}.patch"

    # Ensure patch only touches allowed files: check for filenames in patch
    if grep -E -- "^\+\+\+ b/(go\.mod|go\.sum|chachacrypt\.go)|^--- a/(go\.mod|go\.sum|chachacrypt\.go)|^diff --git a/(go\.mod|go\.sum|chachacrypt\.go) b/(go\.mod|go\.sum|chachacrypt\.go)" "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      :
    else
      echo "AI patch does not appear to target only allowed files; skipping this patch."
      continue
    fi

    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      git apply "ai-fix-${ITER}.patch"
      # Stage only allowed files
      git add "${ALLOWED_FILES[@]}"
      git commit -m "chore: ai: apply automated fixes (iteration ${ITER})" || true
      APPLIED_ANY=true
      # Re-run build & tests
      set +e
      go build ./... > "ai-build-after-iter-${ITER}.log" 2>&1
      BUILD_EXIT=$?
      go test ./... >> "ai-build-after-iter-${ITER}.log" 2>&1
      TEST_EXIT=$?
      set -e
      cat "ai-build-after-iter-${ITER}.log" >> ai-build.log || true
      golangci-lint run --timeout=5m --out-format=json ./... > "ai-lint-after-iter-${ITER}.json" || true
      staticcheck ./... > "ai-staticcheck-after-iter-${ITER}.txt" || true || true
      # If success, break
      if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
        break
      else
        # update ai-diff-after.patch for next iteration with only allowed-files diff
        git diff HEAD~1..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true
        PATCH_CONTENT=$(sed -n '1,400000p' ai-diff-after.patch | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        DIAG_CONTENT=$(sed -n '1,400000p' "$DIAGNOSTIC_SUMMARY" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        continue
      fi
    else
      echo "AI patch failed git apply --check. See ai-fix-${ITER}.log for details."
      continue
    fi
  done
else
  echo "No OPENROUTER_API_KEY; skipping AI attempts."
fi

# Final push if there are committed changes (only allowed files should be committed)
if git status --porcelain | grep -q .; then
  if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
    git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH"
    set_branch_output
  else
    echo "Changes present but GH2_TOKEN/GITHUB_REPOSITORY not available; branch created locally: $BRANCH"
    set_branch_output
  fi
else
  BRANCH=""
  set_branch_output
fi

exit 0
