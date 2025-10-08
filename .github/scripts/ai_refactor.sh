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
  echo "GH2_TOKEN not provided; will not push or create PRs."
fi

if [ -z "$OPENROUTER_API_KEY" ]; then
  echo "OPENROUTER_API_KEY not provided; AI fixes will be skipped."
fi

git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

git fetch --all --prune

git checkout -b "$BRANCH"

export GOFLAGS=-mod=mod

# Update all modules to latest (including major upgrades) and bump go directive to latest stable
go get -u ./... || true
go get go@latest || true
go mod tidy || true

# Save pre-update diff limited to allowed files
git add -A
git diff --staged -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true

# Remove stray built artifacts from repo root (safety)
if [ -f "./chachacrypt" ]; then
  rm -f ./chachacrypt || true
fi

# Restore any changes outside allowed files (do not commit them)
STATUS_LINES=$(git status --porcelain)
if [ -n "$STATUS_LINES" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    file=$(echo "$line" | sed -E 's/^[ MADRCU?]{1,3}//' | sed 's/^[[:space:]]*//')
    skip=false
    for af in "${ALLOWED_FILES[@]}"; do
      if [ "$file" = "$af" ]; then
        skip=true
        break
      fi
    done
    if [ "$skip" = false ]; then
      if git ls-files --error-unmatch -- "$file" >/dev/null 2>&1; then
        git restore --source=HEAD -- "$file" || true
      else
        rm -f -- "$file" || true
      fi
    fi
  done <<< "$STATUS_LINES"
fi

# Stage only allowed files that changed
STAGED=false
for f in "${ALLOWED_FILES[@]}"; do
  if ! git diff --quiet -- "$f" 2>/dev/null; then
    git add "$f"
    STAGED=true
  fi
done

if [ "$STAGED" = false ]; then
  BRANCH=""
  exit 0
fi

git commit -m "chore: update Go toolchain and modules to latest (automated)" || true

git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Build & test (capture logs; do NOT add logs to git)
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
rm -f /tmp/chachacrypt.build || true
set -e

# Lint outputs (do NOT add to git)
golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null || true
staticcheck ./... > ai-staticcheck.txt 2>/dev/null || true || true

# If build & tests passed, push branch and exit
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

# Truncate large files for prompt
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

SYSTEM_PROMPT=$(
cat <<'EOF'
You are qwen3-coder, an expert Go engineer. You will be provided:
- ai-diff-after.patch (recent changes to go.mod/go.sum/chachacrypt.go)
- diagnostics containing build/test/linter output.

CONSTRAINT: You MUST only modify these files: go.mod, go.sum, chachacrypt.go.
Produce a single unified diff (git apply compatible) that only touches those files. If no fix is possible within these constraints, output exactly: NO_PATCH_POSSIBLE
Respond with the unified diff only.
EOF
)

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
      break
    fi

    printf "%s\n" "$PATCH_TEXT" > "ai-fix-${ITER}.patch"

    # Ensure patch touches only allowed files
    if ! grep -E -- "^\+\+\+ b/(go\.mod|go\.sum|chachacrypt\.go)|^--- a/(go\.mod|go\.sum|chachacrypt\.go)|^diff --git a/(go\.mod|go\.sum|chachacrypt\.go) b/(go\.mod|go\.sum|chachacrypt\.go)" "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      continue
    fi

    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      git apply "ai-fix-${ITER}.patch"
      # Revert any modifications outside allowed files (safety)
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

      # Re-run build & tests
      set +e
      go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
      BUILD_EXIT=$?
      go test ./... >> "$AI_BUILD_LOG" 2>&1
      TEST_EXIT=$?
      rm -f /tmp/chachacrypt.build || true
      set -e

      golangci-lint run --timeout=5m --out-format json ./... > ai-lint-after-iter.json || true
      staticcheck ./... > ai-staticcheck-after-iter.txt || true || true

      if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
        break
      else
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

# Finalize: push branch only if commits exist (committed changes limited to allowed files)
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
