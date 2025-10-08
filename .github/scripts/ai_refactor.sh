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

# Write outputs compatibly to GitHub Actions
GITHUB_OUTPUT_FILE="${GITHUB_OUTPUT:-}"
if [ -z "$GITHUB_OUTPUT_FILE" ]; then
  # fallback file when running locally
  GITHUB_OUTPUT_FILE="$(mktemp)"
fi

function set_output() {
  # usage: set_output name value
  echo "$1=$2" >> "$GITHUB_OUTPUT_FILE"
}

trap ':' EXIT

git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

# Ensure remote refs are fetched
git fetch --no-tags --prune origin +refs/heads/*:refs/remotes/origin/* || true

# Create a new branch from the current checked out branch (workflow checks out main)
git checkout -b "$BRANCH"

export GOFLAGS=-mod=mod
export GOPATH="$(go env GOPATH 2>/dev/null || echo "$HOME/go")"
export PATH="$GOPATH/bin:$PATH"

# 1) Update modules to latest (including majors) and bump go directive to latest stable
set -x
go get -u ./... || true
go get go@latest || true
go mod tidy || true
set +x

# Remove repo-root build artifact if present
[ -f "./chachacrypt" ] && rm -f ./chachacrypt || true

# Save pre-update diff for allowed files for diagnostics
git add -A
git diff --staged -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true
git restore --staged . || true

# Determine which allowed files changed
CHANGED_ALLOWED=()
for f in "${ALLOWED_FILES[@]}"; do
  if git status --porcelain -- "$f" | grep -q '.'; then
    CHANGED_ALLOWED+=( "$f" )
  fi
done

# If nothing changed, attempt safe automatic linter fixes (no committing of other files)
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
  # recompute changed allowed files
  CHANGED_ALLOWED=()
  for f in "${ALLOWED_FILES[@]}"; do
    if git status --porcelain -- "$f" | grep -q '.'; then
      CHANGED_ALLOWED+=( "$f" )
    fi
  done
fi

# If still nothing to change -> exit quietly (no branch output)
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  set_output branch ""
  set_output create_pr "false"
  # ensure actions runner sees outputs if running inside GH Actions
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    cat "$GITHUB_OUTPUT_FILE" >> "$GITHUB_OUTPUT"
  fi
  exit 0
fi

# Stage only allowed changed files
git restore --staged . || true
for f in "${CHANGED_ALLOWED[@]}"; do
  git add "$f" || true
done

# Ensure nothing else is staged
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

# Commit allowed files only
if ! git diff --cached --quiet; then
  git commit -m "chore: update Go toolchain & modules to latest (automated)" || true
else
  set_output branch ""
  set_output create_pr "false"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    cat "$GITHUB_OUTPUT_FILE" >> "$GITHUB_OUTPUT"
  fi
  exit 0
fi

# Save post-update diff for diagnostics
git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Build & test — write to artifact log (build to /tmp)
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
rm -f /tmp/chachacrypt.build || true
set -e

# Linter outputs — choose flags depending on golangci-lint major version
get_golangci_major() {
  if ! command -v golangci-lint >/dev/null 2>&1; then
    echo "0"
    return
  fi
  ver=$(golangci-lint --version 2>/dev/null || true)
  # extract first vN
  maj=$(echo "$ver" | grep -Eo 'v[0-9]+' | head -n1 | sed 's/^v//' || true)
  if [ -z "$maj" ]; then
    echo "1"
  else
    echo "$maj"
  fi
}

GOLANGCI_MAJOR=$(get_golangci_major)

if [ "$GOLANGCI_MAJOR" -ge 2 ]; then
  # v2+ uses --output.json.path
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint --version || true
    golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || true
    golangci-lint run --fix --timeout=5m ./... || true
  else
    echo '{"error":"golangci-lint not installed"}' > ai-lint.json
  fi
else
  # v1 uses --out-format
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint --version || true
    # write JSON to file using the older flag form and redirect if necessary
    set +e
    golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      # fallback: run without out-format and capture stdout
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

# Copy/correlate logs for artifacts
cp ai-lint.json ai-lint.json 2>/dev/null || true
cp staticcheck.txt ai-staticcheck.txt 2>/dev/null || true
cp "$AI_BUILD_LOG" ai-build.log 2>/dev/null || true
cp ai-lint.json golangci-lint.json 2>/dev/null || true

# Push branch to origin (required so create-pull-request sees remote ref)
if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
  git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
  git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease
fi

# Decide whether a PR should be created (branch differs from base)
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

# If build failed and AI key provided, attempt AI-assisted fixes (constrained)
if [ "$BUILD_EXIT" -ne 0 ] || [ "$TEST_EXIT" -ne 0 ]; then
  if [ -n "$OPENROUTER_API_KEY" ]; then
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

    # Truncate if very large
    if [ -f ai-diff-after.patch ]; then
      head -n 4000 ai-diff-after.patch > ai-diff-after.patch.tmp || true
      mv ai-diff-after.patch.tmp ai-diff-after.patch || true
    fi
    head -n 4000 "$DIAGNOSTIC_SUMMARY" > "${DIAGNOSTIC_SUMMARY}.tmp" || true
    mv "${DIAGNOSTIC_SUMMARY}.tmp" "$DIAGNOSTIC_SUMMARY" || true

    SYSTEM_PROMPT=$(
cat <<'EOF'
You are tngtech/deepseek-r1t2-chimera, an expert Go engineer.
You will be provided:
- ai-diff-after.patch (recent changes to go.mod/go.sum/chachacrypt.go)
- diagnostics with build/test and linter logs.

CONSTRAINT: You MUST ONLY propose edits to go.mod, go.sum, chachacrypt.go.
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

        # update linter outputs (respecting version)
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
fi

# Final: push branch (already pushed earlier above), ensure outputs available to GH Actions
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  cat "$GITHUB_OUTPUT_FILE" >> "$GITHUB_OUTPUT"
fi

# Clean temporary output file if we created it
if [ -z "${GITHUB_OUTPUT:-}" ] && [ -f "$GITHUB_OUTPUT_FILE" ]; then
  rm -f "$GITHUB_OUTPUT_FILE" || true
fi

exit 0
