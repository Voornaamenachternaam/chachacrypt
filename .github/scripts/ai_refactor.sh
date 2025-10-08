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
BASE_BRANCH="main"

# Determine the correct GH Actions output destination
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  OUTPUT_FILE="${GITHUB_OUTPUT}"
  USING_RUNNER_OUTPUT=true
else
  OUTPUT_FILE="$(mktemp)"
  USING_RUNNER_OUTPUT=false
fi

function set_output() {
  # set_output name value
  local name="$1"
  local value="$2"
  # use the GitHub Actions multiline-safe format only if runner-provided file exists
  if [ "${USING_RUNNER_OUTPUT}" = true ]; then
    printf '%s=%s\n' "$name" "$value" >> "${OUTPUT_FILE}"
  else
    printf '%s=%s\n' "$name" "$value" >> "${OUTPUT_FILE}"
  fi
}

# Ensure git user
git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

# Fetch remote refs to reduce ambiguous ref errors
git fetch --no-tags --prune origin +refs/heads/*:refs/remotes/origin/* || true

# Create new branch from current checkout
git checkout -b "$BRANCH"

export GOFLAGS=-mod=mod
export GOPATH="$(go env GOPATH 2>/dev/null || echo "$HOME/go")"
export PATH="$GOPATH/bin:$PATH"

# Update dependencies and go directive to latest stable
set -x
go get -u ./... || true
go get go@latest || true
go mod tidy || true
set +x

# Remove any repo-root build artifact to avoid accidental commits
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

# If none changed, attempt safe automatic linter fixes (no committing of other files)
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  if ! command -v golangci-lint >/dev/null 2>&1; then
    if command -v go >/dev/null 2>&1; then
      go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || true
      export PATH="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin:$PATH"
    fi
  fi
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=5m ./... || true
  fi
  CHANGED_ALLOWED=()
  for f in "${ALLOWED_FILES[@]}"; do
    if git status --porcelain -- "$f" | grep -q '.'; then
      CHANGED_ALLOWED+=( "$f" )
    fi
  done
fi

# If nothing changed among allowed files -> exit (no PR)
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  set_output branch ""
  set_output create_pr "false"
  # emit outputs to runner if using runner
  if [ "${USING_RUNNER_OUTPUT}" = true ]; then
    :
  else
    cat "${OUTPUT_FILE}"
  fi
  exit 0
fi

# Stage exactly allowed changed files
git restore --staged . || true
for f in "${CHANGED_ALLOWED[@]}"; do
  git add "$f" || true
done

# Ensure only allowed files are staged, unstage anything else
STAGED_FILES=$(git diff --cached --name-only || true)
for sf in $STAGED_FILES; do
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

# Commit allowed files only (if any)
if ! git diff --cached --quiet; then
  git commit -m "chore: update Go toolchain & modules to latest (automated)" || true
else
  set_output branch ""
  set_output create_pr "false"
  if [ "${USING_RUNNER_OUTPUT}" = true ]; then
    :
  else
    cat "${OUTPUT_FILE}"
  fi
  exit 0
fi

# Save post-update diff for diagnostics
git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Build & test — logs go to ai-build.log; build to /tmp to avoid repo-root binaries
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
rm -f /tmp/chachacrypt.build || true
set -e

# Determine golangci-lint major and run appropriate flags
get_golangci_major() {
  if ! command -v golangci-lint >/dev/null 2>&1; then
    echo "0"
    return
  fi
  ver=$(golangci-lint --version 2>/dev/null || true)
  maj=$(echo "$ver" | grep -Eo 'v[0-9]+' | head -n1 | sed 's/^v//' || true)
  if [ -z "$maj" ]; then
    echo "1"
  else
    echo "$maj"
  fi
}

GOLANGCI_MAJOR=$(get_golangci_major)

if [ "$GOLANGCI_MAJOR" -ge 2 ]; then
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint --version || true
    golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || true
    golangci-lint run --fix --timeout=5m ./... || true
  else
    echo '{"error":"golangci-lint not installed"}' > ai-lint.json
  fi
else
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint --version || true
    set +e
    golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      golangci-lint run --timeout=5m ./... > ai-lint.json || true
    fi
    golangci-lint run --fix --timeout=5m ./... || true
  else
    echo '{"error":"golangci-lint not installed"}' > ai-lint.json
  fi
fi

# staticcheck
if command -v staticcheck >/dev/null 2>&1; then
  staticcheck ./... > staticcheck.txt || true
else
  echo "staticcheck not available" > staticcheck.txt
fi

# Copy logs to canonical names for artifacts
cp ai-lint.json ai-lint.json 2>/dev/null || true
cp staticcheck.txt ai-staticcheck.txt 2>/dev/null || true
cp "$AI_BUILD_LOG" ai-build.log 2>/dev/null || true
cp ai-lint.json golangci-lint.json 2>/dev/null || true

# Push branch to origin (so create-pull-request sees remote ref)
if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
  git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
  git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease
fi

# Decide if PR is needed (branch differs from base)
set +e
git fetch origin "$BASE_BRANCH" --depth=1 || true
COMMITS_AHEAD=$(git rev-list --right-only --count "origin/${BASE_BRANCH}...refs/heads/${BRANCH}" 2>/dev/null || true)
set -e

if [ -n "$COMMITS_AHEAD" ] && [ "$COMMITS_AHEAD" -gt 0 ] 2>/dev/null; then
  set_output branch "$BRANCH"
  set_output create_pr "true"
else
  set_output branch "$BRANCH"
  set_output create_pr "false"
fi

# If build/test failed and AI key provided, attempt AI-assisted fixes (constrained to allowed files)
if { [ "$BUILD_EXIT" -ne 0 ] || [ "$TEST_EXIT" -ne 0 ]; } && [ -n "$OPENROUTER_API_KEY" ]; then
  DIAGNOSTIC_SUMMARY="ai-diagnostics.txt"
  {
    echo "=== Build & Test ==="
    cat ai-build.log 2>/dev/null || true
    echo
    echo "=== golangci-lint ==="
    cat ai-lint.json 2>/dev/null || true
    echo
    echo "=== staticcheck ==="
    cat staticcheck.txt 2>/dev/null || true
  } > "$DIAGNOSTIC_SUMMARY"

  # Truncate to safe size
  head -n 4000 ai-diff-after.patch > ai-diff-after.patch.tmp 2>/dev/null || true
  if [ -f ai-diff-after.patch.tmp ]; then mv ai-diff-after.patch.tmp ai-diff-after.patch || true; fi
  head -n 4000 "$DIAGNOSTIC_SUMMARY" > "${DIAGNOSTIC_SUMMARY}.tmp" 2>/dev/null || true
  if [ -f "${DIAGNOSTIC_SUMMARY}.tmp" ]; then mv "${DIAGNOSTIC_SUMMARY}.tmp" "$DIAGNOSTIC_SUMMARY" || true; fi

  SYSTEM_PROMPT=$(
cat <<'EOF'
You are tngtech/deepseek-r1t2-chimera, an expert Go engineer.
You will be given ai-diff-after.patch and diagnostics.
CONSTRAINT: You MUST ONLY propose edits to go.mod, go.sum, and/or chachacrypt.go.
Return exactly a single unified diff (git apply format) touching only these files,
or the single line: NO_PATCH_POSSIBLE
EOF
)

  PATCH_CONTENT=$(sed -n '1,400000p' ai-diff-after.patch | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' || true)
  DIAG_CONTENT=$(sed -n '1,400000p' "$DIAGNOSTIC_SUMMARY" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' || true)

  ITER=0
  while [ "$ITER" -lt "$MAX_ITER" ]; do
    ITER=$((ITER+1))
    RESPONSE_FILE="ai-response-${ITER}.json"
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

    curl -sS -X POST "$OPENROUTER_ENDPOINT" \
      -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" -o "$RESPONSE_FILE" || true

    PATCH_TEXT=""
    if command -v jq >/dev/null 2>&1; then
      PATCH_TEXT=$(jq -r '.choices[0].message.content // .choices[0].text // .output[0].content[0].text // ""' "$RESPONSE_FILE" 2>/dev/null || true)
    else
      PATCH_TEXT=$(sed -n '1,200000p' "$RESPONSE_FILE" || true)
    fi

    echo "$PATCH_TEXT" > "ai-fix-${ITER}.log" || true

    if echo "$PATCH_TEXT" | tr -d '\r' | grep -q '^NO_PATCH_POSSIBLE$'; then
      break
    fi

    printf "%s\n" "$PATCH_TEXT" > "ai-fix-${ITER}.patch"

    # Validate patch touches only allowed files
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

    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      git apply "ai-fix-${ITER}.patch"
      # ensure only allowed files changed
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

      # Stage & commit allowed files only
      for f in "${ALLOWED_FILES[@]}"; do
        if ! git diff --quiet -- "$f" 2>/dev/null; then
          git add "$f"
        fi
      done
      git commit -m "chore: ai: apply automated fixes (iteration ${ITER})" || true

      # Re-run build & tests and append logs
      set +e
      go build -o /tmp/chachacrypt.build ./... >> ai-build.log 2>&1
      BUILD_EXIT=$?
      go test ./... >> ai-build.log 2>&1
      TEST_EXIT=$?
      rm -f /tmp/chachacrypt.build || true
      set -e

      # Update linter outputs
      if [ "$GOLANGCI_MAJOR" -ge 2 ]; then
        golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || true
      else
        set +e
        golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null
        set -e
      fi
      staticcheck ./... > ai-staticcheck.txt || true

      if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
        break
      else
        git diff HEAD~1..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true
        continue
      fi
    else
      continue
    fi
  done
fi

# Emit outputs to GitHub Actions runner if appropriate
if [ "${USING_RUNNER_OUTPUT}" = true ]; then
  # nothing extra needed — we've already appended to $GITHUB_OUTPUT directly
  :
else
  # print outputs to stdout (useful for local testing)
  cat "${OUTPUT_FILE}"
fi

# If we created a temp output file locally, remove it
if [ "${USING_RUNNER_OUTPUT}" = false ] && [ -f "${OUTPUT_FILE}" ]; then
  rm -f "${OUTPUT_FILE}" || true
fi

exit 0
