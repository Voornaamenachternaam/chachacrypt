#!/usr/bin/env bash
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

GITHUB_OUTPUT="${GITHUB_OUTPUT:-.github_action_output_tmp}"
# When running in GH actions, GITHUB_OUTPUT file is provided; otherwise create a temp.
if [ -z "${GITHUB_OUTPUT:-}" ]; then
  GITHUB_OUTPUT="$(mktemp)"
fi

function set_output() {
  # safe write to GITHUB_OUTPUT
  echo "$1=$2" >> "$GITHUB_OUTPUT"
}

trap 'rm -f "${GITHUB_OUTPUT}" 2>/dev/null || true' EXIT

git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

# Ensure fetch of remote refs
git fetch --no-tags --prune origin +refs/heads/*:refs/remotes/origin/* || true

# Start fresh branch from current checked-out branch (should be main from checkout step)
BASE_BRANCH="main"
git checkout -b "$BRANCH"

export GOFLAGS=-mod=mod
export GOPATH="$(go env GOPATH)"
export PATH="$GOPATH/bin:$PATH"

# Update dependencies and go directive to latest stable
set -x
go get -u ./... || true
go get go@latest || true
go mod tidy || true
set +x

# Remove any build binary left in workspace to avoid accidental commits
[ -f "./chachacrypt" ] && rm -f ./chachacrypt || true

# Save pre-update allowed-file diff for diagnostics
git add -A
git diff --staged -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true
git restore --staged . || true

# Determine which allowed files changed (unstaged)
CHANGED_ALLOWED=()
for f in "${ALLOWED_FILES[@]}"; do
  if git status --porcelain -- "$f" | grep -q '.'; then
    CHANGED_ALLOWED+=( "$f" )
  fi
done

# If none changed, try automated linter fixes
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  if ! command -v golangci-lint >/dev/null 2>&1; then
    # attempt to install golangci-lint so we can run --fix
    if command -v go >/dev/null 2>&1; then
      go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || true
      export PATH="$(go env GOPATH)/bin:$PATH"
    fi
  fi
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=5m ./... || true
  fi
  # recompute changed allowed files
  CHANGED_ALLOWED=()
  for f in "${ALLOWED_FILES[@]}"; do
    if git status --porcelain -- "$f" | grep -q '.'; then
      CHANGED_ALLOWED+=( "$f" )
    fi
  done
fi

# If nothing changed among allowed files -> nothing to do
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  set_output branch ""
  set_output create_pr "false"
  exit 0
fi

# Stage exactly allowed files that changed
git restore --staged . || true
for f in "${CHANGED_ALLOWED[@]}"; do
  git add "$f" || true
done

# Unstage anything not in ALLOWED_FILES to ensure safety
STAGED=$(git diff --cached --name-only || true)
for sf in $STAGED; do
  ok=false
  for af in "${ALLOWED_FILES[@]}"; do
    if [ "$sf" = "$af" ]; then
      ok=true
      break
    fi
  done
  if [ "$ok" = false ]; then
    git restore --staged -- "$sf" || true
  fi
done

# Commit if there are staged changes
if ! git diff --cached --quiet; then
  git commit -m "chore: update Go toolchain & modules to latest (automated)" || true
else
  set_output branch ""
  set_output create_pr "false"
  exit 0
fi

# Save post-update allowed-file diff (for diagnostics)
git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Collect build & test logs
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
rm -f /tmp/chachacrypt.build || true
set -e

# Linter outputs (use modern flags)
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint --version || true
  golangci-lint run --timeout=5m --output.json.path=golangci-lint.json ./... || true
else
  echo '{"error":"golangci-lint not installed"}' > golangci-lint.json
fi

if command -v staticcheck >/dev/null 2>&1; then
  staticcheck ./... > staticcheck.txt || true
else
  echo "staticcheck not available" > staticcheck.txt
fi

# Copy logs for artifacts
cp golangci-lint.json ai-lint.json 2>/dev/null || true
cp staticcheck.txt ai-staticcheck.txt 2>/dev/null || true
cp "$AI_BUILD_LOG" ai-build.log 2>/dev/null || true

# If build and tests passed, push branch and mark create_pr true
if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
  if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
    git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH"
    # Compare branch with base to decide if PR needed
    git fetch origin "$BASE_BRANCH" --depth=1 || true
    COMMITS_AHEAD=$(git rev-list --right-only --count "origin/${BASE_BRANCH}...refs/heads/${BRANCH}" || true)
    if [ -n "$COMMITS_AHEAD" ] && [ "$COMMITS_AHEAD" -gt 0 ] 2>/dev/null; then
      set_output branch "$BRANCH"
      set_output create_pr "true"
    else
      set_output branch "$BRANCH"
      set_output create_pr "false"
    fi
  else
    set_output branch "$BRANCH"
    set_output create_pr "false"
  fi
  exit 0
fi

# If build failed, attempt AI-assisted fixes (only allowed files)
DIAGNOSTIC_SUMMARY="ai-diagnostics.txt"
{
  echo "=== Build & Test Log ==="
  cat ai-build.log 2>/dev/null || true
  echo
  echo "=== golangci-lint JSON ==="
  cat golangci-lint.json 2>/dev/null || true
  echo
  echo "=== staticcheck ==="
  cat staticcheck.txt 2>/dev/null || true
} > "$DIAGNOSTIC_SUMMARY"

# Truncate potentially huge files
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

# Prepare AI system prompt
SYSTEM_PROMPT=$(
cat <<'EOF'
You are tngtech/deepseek-r1t2-chimera, an expert Go engineer.
You will be given diagnostics and a current diff (ai-diff-after.patch).
CONSTRAINT: You MUST ONLY propose edits to go.mod, go.sum, and/or chachacrypt.go.
Return exactly a single unified diff (git apply format) touching only these files,
or the single line: NO_PATCH_POSSIBLE
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
      PATCH_TEXT=$(jq -r '.choices[0].message.content // .choices[0].text // .output[0].content[0].text // ""' "$RESPONSE_FILE" 2>/dev/null || true)
    else
      PATCH_TEXT=$(sed -n '1,200000p' "$RESPONSE_FILE" || true)
    fi

    echo "$PATCH_TEXT" > "ai-fix-${ITER}.log"

    if echo "$PATCH_TEXT" | tr -d '\r' | grep -q '^NO_PATCH_POSSIBLE$'; then
      break
    fi

    printf "%s\n" "$PATCH_TEXT" > "ai-fix-${ITER}.patch"

    # Validate that patch only touches allowed files
    FILES_IN_PATCH=$(grep -E '^(diff --git a/|^\+\+\+ b/|^--- a/)' "ai-fix-${ITER}.patch" | sed -E 's/^diff --git a\/([^ ]+) b\/([^ ]+)$/\1\n\2/; s/^\+\+\+ b\/(.*)$/\1/; s/^--- a\/(.*)$/\1/' | sed '/^$/d' | sort -u || true)

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

    # Validate patch applies
    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      git apply "ai-fix-${ITER}.patch"

      # Ensure only allowed files changed; revert others
      STATUS_AFTER=$(git status --porcelain || true)
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

      # Stage allowed files only
      for f in "${ALLOWED_FILES[@]}"; do
        if ! git diff --quiet -- "$f" 2>/dev/null; then
          git add "$f"
        fi
      done

      git commit -m "chore: ai: apply automated fixes (iteration ${ITER})" || true
      APPLIED_ANY=true

      # Re-run build & tests and append logs
      set +e
      go build -o /tmp/chachacrypt.build ./... >> ai-build.log 2>&1
      BUILD_EXIT=$?
      go test ./... >> ai-build.log 2>&1
      TEST_EXIT=$?
      rm -f /tmp/chachacrypt.build || true
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

# Final push of branch only if commits exist and allowed files are committed
if git rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
  # Ensure only allowed files are staged/committed
  if ! git diff --cached --name-only | grep -Ev "^($(IFS=\|; echo "${ALLOWED_FILES[*]}"))$" >/dev/null 2>&1; then
    # safe: nothing else staged
    :
  fi

  if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
    git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
    git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease
    # Determine if PR should be created (branch differs from base)
    git fetch origin "$BASE_BRANCH" --depth=1 || true
    COMMITS_AHEAD=$(git rev-list --right-only --count "origin/${BASE_BRANCH}...refs/heads/${BRANCH}" || true)
    if [ -n "$COMMITS_AHEAD" ] && [ "$COMMITS_AHEAD" -gt 0 ] 2>/dev/null; then
      set_output branch "$BRANCH"
      set_output create_pr "true"
    else
      set_output branch "$BRANCH"
      set_output create_pr "false"
    fi
  else
    set_output branch "$BRANCH"
    set_output create_pr "false"
  fi
else
  set_output branch ""
  set_output create_pr "false"
fi

# Write outputs to GITHUB_OUTPUT in actions runner if available
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  # nothing - already appended above
  :
fi

exit 0
