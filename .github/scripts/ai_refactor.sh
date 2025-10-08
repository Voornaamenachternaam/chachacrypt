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
MODEL="tngtech/deepseek-r1t2-chimera:free"
OPENROUTER_ENDPOINT="${OPENROUTER_ENDPOINT:-https://api.openrouter.ai/v1/chat/completions}"

ALLOWED_FILES=( "go.mod" "go.sum" "chachacrypt.go" )

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
  echo "GH2_TOKEN not provided; push/PR steps will be skipped."
fi

if [ -z "$OPENROUTER_API_KEY" ]; then
  echo "OPENROUTER_API_KEY not provided; AI fixes will be skipped."
fi

git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

git fetch --all --prune

# Work on a new branch but do not push unless allowed-file changes are committed
git checkout -b "$BRANCH"

# Ensure GOFLAGS
export GOFLAGS=-mod=mod

# Update all modules to latest (including major updates) and bump go directive to latest stable
set -x
go get -u ./... || true
go get go@latest || true
go mod tidy || true
set +x

# Remove any stray built binary in repo root so it doesn't get accidentally committed
[ -f "./chachacrypt" ] && rm -f ./chachacrypt || true

# Save pre-update diff for allowed files
git add -A
git diff --staged -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true
git reset --quiet

# Determine which allowed files changed (unstaged changes)
CHANGED_ALLOWED=()
for f in "${ALLOWED_FILES[@]}"; do
  if git diff --name-only -- "$f" | grep -q '.'; then
    CHANGED_ALLOWED+=("$f")
  fi
done

# If no allowed files changed, try to run safe automatic fixes (linters) but do not commit non-allowed files
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=5m ./... || true
  fi
  # recompute changed allowed files
  for f in "${ALLOWED_FILES[@]}"; do
    if git diff --name-only -- "$f" | grep -q '.'; then
      CHANGED_ALLOWED+=("$f")
    fi
  done
fi

# If still nothing to change, do not create branch/PR
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  BRANCH=""
  exit 0
fi

# Stage only allowed changed files
for f in "${CHANGED_ALLOWED[@]}"; do
  git add "$f" || true
done

git commit -m "chore: update Go toolchain and modules to latest (automated)" || true

# Save post-update diff limited to allowed files
git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Capture build & test logs (do not add logs to git)
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
go build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
set -e

# Linter outputs (do not add to git). Use modern golangci-lint flags.
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || true
else
  echo "golangci-lint not available" > ai-lint.json
fi
if command -v staticcheck >/dev/null 2>&1; then
  staticcheck ./... > ai-staticcheck.txt || true
else
  echo "staticcheck not available" > ai-staticcheck.txt
fi

# If build & tests passed, push branch (only allowed files committed) and exit
if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
  if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
    git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH"
    set_branch_output
  else
    set_branch_output
  fi
  exit 0
fi

# Prepare diagnostics for AI
DIAGNOSTIC_SUMMARY="ai-diagnostics.txt"
{
  echo "=== Build & Test Output ==="
  cat "$AI_BUILD_LOG" 2>/dev/null || true
  echo
  echo "=== golangci-lint (json) ==="
  cat ai-lint.json 2>/dev/null || true
  echo
  echo "=== staticcheck ==="
  cat ai-staticcheck.txt 2>/dev/null || true
} > "$DIAGNOSTIC_SUMMARY"

# Truncate large files for prompt to a safe size
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

# Prepare system prompt (AI must only change allowed files)
read -r -d '' SYSTEM_PROMPT <<'SYS' || true
You are tngtech/deepseek-r1t2-chimera, an expert Go engineer. You will be given:
- a git patch file (ai-diff-after.patch) representing recent changes to go.mod/go.sum/chachacrypt.go
- build/test failure logs and linter outputs.

CONSTRAINT: You MUST ONLY propose edits to these files: go.mod, go.sum, chachacrypt.go.
Produce a single unified diff (git apply format) that only touches those files. If no fix is possible within these constraints, output exactly the single line: NO_PATCH_POSSIBLE
Respond with the unified diff only.
SYS

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
    {"role":"user","content":"Patch (ai-diff-after.patch):\n\n${PATCH_CONTENT}\n\nDiagnostics:\n\n${DIAG_CONTENT}\n\nPlease produce a single unified patch that modifies only go.mod, go.sum and/or chachacrypt.go. If not possible, reply exactly: NO_PATCH_POSSIBLE"}
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

    # Extract text content from common response shapes
    PATCH_TEXT=""
    if command -v jq >/dev/null 2>&1; then
      PATCH_TEXT=$(jq -r '.choices[0].message.content // .choices[0].text // .output[0].content[0].text // ""' "$RESPONSE_FILE" 2>/dev/null || true)
    else
      PATCH_TEXT=$(sed -n '1,200000p' "$RESPONSE_FILE" || true)
    fi

    echo "$PATCH_TEXT" > "ai-fix-${ITER}.log"

    if echo "$PATCH_TEXT" | tr -d '\r' | grep -q '^NO_PATCH_POSSIBLE$'; then
      break
    fi

    printf "%s\n" "$PATCH_TEXT" > "ai-fix-${ITER}.patch"

    # Strictly extract filenames referenced in the patch
    FILES_IN_PATCH=$(grep -E '^(diff --git a/|^\+\+\+ b/|^--- a/)' "ai-fix-${ITER}.patch" | sed -E 's/^diff --git a\/([^ ]+) b\/([^ ]+)$/\1\n\2/; s/^\+\+\+ b\/(.*)$/\1/; s/^--- a\/(.*)$/\1/' | sed '/^$/d' | sort -u || true)

    # Ensure all files in patch are within allowed list
    INVALID=false
    for pfile in $FILES_IN_PATCH; do
      match=false
      for af in "${ALLOWED_FILES[@]}"; do
        if [ "$pfile" = "$af" ]; then
          match=true
          break
        fi
      done
      if [ "$match" = false ]; then
        INVALID=true
        break
      fi
    done

    if [ "$INVALID" = true ]; then
      continue
    fi

    # Validate patch with git apply check
    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      git apply "ai-fix-${ITER}.patch"
      # After applying, ensure only allowed files changed; revert any others
      STATUS_AFTER=$(git status --porcelain)
      if [ -n "$STATUS_AFTER" ]; then
        while IFS= read -r line; do
          [ -z "$line" ] && continue
          file=$(echo "$line" | sed -E 's/^[ MADRCU?]{1,3}//' | sed 's/^[[:space:]]*//')
          allowed=false
          for af in "${ALLOWED_FILES[@]}"; do
            if [ "$file" = "$af" ]; then
              allowed=true
              break
            fi
          done
          if [ "$allowed" = false ]; then
            if git ls-files --error-unmatch -- "$file" >/dev/null 2>&1; then
              git restore --source=HEAD -- "$file" || true
            else
              rm -f -- "$file" || true
            fi
          fi
        done <<< "$STATUS_AFTER"
      fi

      # Stage and commit allowed files only
      for f in "${ALLOWED_FILES[@]}"; do
        if ! git diff --quiet -- "$f" 2>/dev/null; then
          git add "$f"
        fi
      done
      git commit -m "chore: ai: apply automated fixes (iteration ${ITER})" || true
      APPLIED_ANY=true

      # Re-run build & tests and update logs
      set +e
      go build ./... >> "$AI_BUILD_LOG" 2>&1
      BUILD_EXIT=$?
      go test ./... >> "$AI_BUILD_LOG" 2>&1
      TEST_EXIT=$?
      set -e

      # Update lint outputs
      if command -v golangci-lint >/dev/null 2>&1; then
        golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || true
      fi
      if command -v staticcheck >/dev/null 2>&1; then
        staticcheck ./... > ai-staticcheck.txt || true
      fi

      if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
        break
      else
        # refresh ai-diff-after.patch with allowed-files-only diff for next iteration
        git diff HEAD~1..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true
        PATCH_CONTENT=$(sed -n '1,400000p' ai-diff-after.patch | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        DIAG_CONTENT=$(sed -n '1,400000p' "$DIAGNOSTIC_SUMMARY" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        continue
      fi
    else
      continue
    fi
  done
fi

# Final step: push only if commits exist (committed changes limited to allowed files)
if git status --porcelain | grep -q .; then
  if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
    git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH"
    set_branch_output
  else
    set_branch_output
  fi
else
  BRANCH=""
  set_branch_output
fi

exit 0
