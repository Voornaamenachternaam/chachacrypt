#!/usr/bin/env bash
# /.github/scripts/ai_refactor.sh
# AI-assisted dependency & Go toolchain updater for chachacrypt-main
# - Updates all modules (including major upgrades) to latest
# - Bumps `go` directive in go.mod to latest stable
# - Tries to build + test; if failures occur, queries OpenRouter (qwen/qwen3-coder:free)
#   for a unified diff patch. Applies up to MAX_ITER iterations.
# - Commits to a new branch and pushes. Outputs the branch name to GITHUB_OUTPUT
#
# NOTE: This script deliberately never fails the overall CI (exits 0) so the workflow can
# continue to collect artifacts and create PRs. It logs outputs to files for inspection.

set -euo pipefail

# Configuration
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

# output branch for workflow steps
function set_branch_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "branch=${BRANCH}" >> "$GITHUB_OUTPUT"
  else
    # older runner compatibility
    echo "::set-output name=branch::${BRANCH}" || true
  fi
}

# Safe exit helper: always set branch output (empty if nothing to push)
function finish_success() {
  # ensure branch output is written
  set_branch_output || true
  exit 0
}

trap 'finish_success' EXIT

# Ensure tokens present
if [ -z "$GH2_TOKEN" ]; then
  echo "GH2_TOKEN not provided; continuing but cannot push or create PR."
fi

if [ -z "$OPENROUTER_API_KEY" ]; then
  echo "OPENROUTER_API_KEY not provided; AI fixes will be skipped."
fi

# Configure git
git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

# Ensure we have full history for diffs & commits
git fetch --all --prune

# Create branch from current HEAD
git checkout -b "$BRANCH"

# -------- Update dependencies & go directive --------

echo "==> Updating Go modules to latest (including major upgrades) ..."
set -x
# Upgrade all modules to the latest versions (including majors/minors)
GOFLAGS=-mod=mod go get -u ./... || true

# Also ensure go directive in go.mod is bumped to latest stable Go
# `go get go@latest` bumps the go directive in go.mod
GOFLAGS=-mod=mod go get go@latest || true

# Tidy
go mod tidy

# Save pre-AI diff
git add -A
git diff --staged > ai-diff-before.patch || true

# If no changes after updates, we can skip AI, but still attempt to bump minor fixes via linter/fix
if git diff --staged --quiet; then
  echo "No module/go directive changes detected after update."
  # still attempt to run safe auto-fixes with golangci-lint --fix (if available)
  if command -v golangci-lint >/dev/null 2>&1; then
    echo "Running golangci-lint --fix to apply safe automated fixes..."
    golangci-lint run --fix --timeout=5m ./... || true
  fi
  # commit if any of those fixed something
  git add -A
  if git diff --staged --quiet; then
    echo "No changes to commit after linters either. Exiting without creating branch updates."
    # leave branch output blank to signal no PR needed
    BRANCH=""
    exit 0
  fi
fi

# Commit the dependency updates
git commit -m "chore: update Go toolchain and modules to latest (automated)" || true

# Save post-update diff
git diff HEAD^..HEAD > ai-diff-after.patch || true

# -------- Build & Lint initial run --------

echo "==> Attempting initial build and test..."
set +e
go build ./... > ai-build.log 2>&1
BUILD_EXIT=$?
go test ./... >> ai-build.log 2>&1
TEST_EXIT=$?
set -e

# Run linters and collect outputs (non-fatal)
golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null || true
staticcheck ./... > ai-staticcheck.txt 2>/dev/null || true || true

# If build & tests passed, push branch and exit (PR creation performed by workflow action)
if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
  echo "Build and tests passed after dependency update. Pushing branch..."
  if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
    # set remote to use token for push (do not echo token)
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
    git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH"
    set_branch_output
  else
    echo "No GH2_TOKEN or GITHUB_REPOSITORY => not pushing branch."
  fi
  exit 0
fi

echo "Build or tests failed; collecting diagnostics for AI..."

# Collect diagnostics
BUILD_LOG="ai-build.log"
LINT_LOG="ai-lint.json"
STATICCHECK_LOG="ai-staticcheck.txt"
DIAGNOSTIC_SUMMARY="ai-diagnostics.txt"

echo "=== Build output ===" > "$DIAGNOSTIC_SUMMARY"
cat "$BUILD_LOG" >> "$DIAGNOSTIC_SUMMARY" || true
echo "" >> "$DIAGNOSTIC_SUMMARY"
echo "=== golangci-lint output (json) ===" >> "$DIAGNOSTIC_SUMMARY"
cat "$LINT_LOG" >> "$DIAGNOSTIC_SUMMARY" || true
echo "" >> "$DIAGNOSTIC_SUMMARY"
echo "=== staticcheck output ===" >> "$DIAGNOSTIC_SUMMARY"
cat "$STATICCHECK_LOG" >> "$DIAGNOSTIC_SUMMARY" || true

# Prepare the diff to send to the AI (use the patch produced by our update commit)
PATCH_TO_SEND="ai-diff-after.patch"
if [ ! -s "$PATCH_TO_SEND" ]; then
  git diff HEAD~1..HEAD > "$PATCH_TO_SEND" || true
fi

# Limit sizes to avoid huge requests: trim files if needed
truncate_limit() {
  local file="$1"
  local max_lines="$2"
  if [ -f "$file" ]; then
    local lines
    lines=$(wc -l < "$file" || echo 0)
    if [ "$lines" -gt "$max_lines" ]; then
      echo "Truncating $file to first $max_lines lines for the AI prompt"
      head -n "$max_lines" "$file" > "${file}.truncated"
      mv "${file}.truncated" "$file"
    fi
  fi
}

truncate_limit "$PATCH_TO_SEND" 4000
truncate_limit "$DIAGNOSTIC_SUMMARY" 4000

# Prepare prompt for AI
SYSTEM_PROMPT=$(
cat <<'EOF'
You are qwen3-coder, an expert Go engineer. You will be given:
- a git patch "ai-diff-after.patch" that contains the update in dependencies and the go.mod change,
- build and test failure logs,
- linter outputs (golangci-lint + staticcheck).

Your job:
1) Analyze the failures and provide a unified diff (patch) that, when applied to the repository root, will attempt to fix the build/test/lint issues and restore compatibility with the new dependency versions and Go toolchain.
2) Only output a single unified diff in standard "git apply" / "patch" format (no explanation). If no fix is possible, output the single line: "NO_PATCH_POSSIBLE".
3) Keep changes minimal and targeted. Prefer code modifications over downgrading dependencies. Do not add or remove entire files unless necessary.
4) Preserve existing behavior and tests where possible.
5) If multiple alternative fixes exist, prefer the one with least code churn.
6) If you change module versions or imports, ensure go.mod/go.sum are consistent and small. But do NOT alter go.mod directly in the patch unless required.

Respond with the unified patch only.
EOF
)

# Read files content for prompt
PATCH_CONTENT=$(sed -n '1,400000p' "$PATCH_TO_SEND" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' )
DIAG_CONTENT=$(sed -n '1,400000p' "$DIAGNOSTIC_SUMMARY" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' )

# AI loop: request patches and apply until build passes or max iters
ITER=0
APPLIED_ANY=false

if [ -z "$OPENROUTER_API_KEY" ]; then
  echo "No OPENROUTER_API_KEY; skipping AI fix attempts."
else
  while [ "$ITER" -lt "$MAX_ITER" ]; do
    ITER=$((ITER+1))
    echo "AI iteration $ITER / $MAX_ITER"

    # compose JSON payload for OpenRouter chat completion
    read -r -d '' PAYLOAD <<EOF || true
{
  "model": "${MODEL}",
  "messages": [
    {"role":"system","content":"${SYSTEM_PROMPT}"},
    {"role":"user","content":"Repository patch (ai-diff-after.patch):\n\n${PATCH_CONTENT}\n\nBuild & test & linter diagnostics:\n\n${DIAG_CONTENT}\n\nPlease produce a single unified patch (git apply compatible) that attempts to fix the issues. If not possible, reply with exactly: NO_PATCH_POSSIBLE"}
  ],
  "temperature": 0.0,
  "max_tokens": 32768
}
EOF

    # Call OpenRouter
    RESPONSE_FILE="ai-response-${ITER}.json"
    curl -sS -X POST "$OPENROUTER_ENDPOINT" \
      -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" \
      -o "$RESPONSE_FILE" || true

    # Extract text from response: support both "choices" style and "output" style
    PATCH_TEXT=""
    if command -v jq >/dev/null 2>&1; then
      # try typical chat-completions structure
      PATCH_TEXT=$(jq -r '.choices[0].message.content // .choices[0].text // ""' "$RESPONSE_FILE" 2>/dev/null || true)
      if [ -z "$PATCH_TEXT" ] || [ "$PATCH_TEXT" = "null" ]; then
        PATCH_TEXT=$(jq -r '.output[0].content[0].text // ""' "$RESPONSE_FILE" 2>/dev/null || true)
      fi
    else
      # fallback crude extraction
      PATCH_TEXT=$(sed -n '1,200000p' "$RESPONSE_FILE" || true)
    fi

    # Save raw AI response
    echo "$PATCH_TEXT" > "ai-fix-${ITER}.log"

    # Check if AI declared no patch possible
    if echo "$PATCH_TEXT" | tr -d '\r' | grep -q '^NO_PATCH_POSSIBLE$'; then
      echo "AI responded: NO_PATCH_POSSIBLE"
      break
    fi

    # Try to extract first unified diff from response (lines starting with --- a/ or *** or diff --git)
    # Normalize line endings
    printf "%s\n" "$PATCH_TEXT" > "ai-fix-${ITER}.patch"

    # Validate patch
    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      echo "AI patch appears valid; applying..."
      git apply "ai-fix-${ITER}.patch"
      # stage and commit
      git add -A
      git commit -m "chore: ai: apply automated fixes (iteration ${ITER})" || true
      APPLIED_ANY=true
      # Re-run build + tests
      set +e
      go build ./... > ai-build-after-iter-${ITER}.log 2>&1
      BUILD_EXIT=$?
      go test ./... >> ai-build-after-iter-${ITER}.log 2>&1
      TEST_EXIT=$?
      set -e
      # Collect new diagnostics
      cat ai-build-after-iter-${ITER}.log >> "$DIAGNOSTIC_SUMMARY" || true
      golangci-lint run --timeout=5m --out-format json ./... > ai-lint-after-iter-${ITER}.json || true
      staticcheck ./... > ai-staticcheck-after-iter-${ITER}.txt || true || true
      # If build & tests pass, break
      if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
        echo "Build and tests passed after AI iteration $ITER"
        break
      else
        echo "Build/tests still failing after AI iteration $ITER; continuing loop if iterations remain."
        # Prepare new patch and diagnostics for next iteration
        git diff HEAD~1..HEAD > ai-diff-after.patch || true
        PATCH_CONTENT=$(sed -n '1,400000p' ai-diff-after.patch | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' )
        DIAG_CONTENT=$(sed -n '1,400000p' "$DIAGNOSTIC_SUMMARY" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' )
        continue
      fi
    else
      echo "AI patch failed git apply check. Saving AI output for inspection: ai-fix-${ITER}.log"
      # try to extract a diff block heuristically and write to .patch, but skip if invalid
      # Do not fail; continue to next iteration to ask AI again
      continue
    fi
  done
fi

# After AI attempts, final push of branch (if any changes and token available)
if git status --porcelain | grep -q .; then
  if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
    echo "Pushing branch ${BRANCH} to ${GIT_PUSH_REMOTE}..."
    # set remote to use token for push (do not echo token)
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
    git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH"
    set_branch_output
  else
    echo "Changes present but no GH2_TOKEN/GITHUB_REPOSITORY: not pushing (local changes only)."
    # still output branch so workflow knows what branch was used
    set_branch_output
  fi
else
  echo "No changes to push on branch ${BRANCH}."
  # clear branch to indicate no PR needed
  BRANCH=""
  set_branch_output
fi

# All done. The trap will call finish_success which emits branch output and exits 0.
exit 0
