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
BASE_BRANCH="main"

# Write outputs for GitHub Actions safely: append directly to $GITHUB_OUTPUT if provided.
function set_output() {
  local name="$1"
  local value="$2"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_OUTPUT"
  else
    # local execution: print to stdout so callers can capture
    printf '%s=%s\n' "$name" "$value"
  fi
}

# Configure git author
git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

# Fetch origin refs and ensure we branch from latest main
git fetch --no-tags --prune origin +refs/heads/*:refs/remotes/origin/* || true
git fetch --no-tags --prune origin "$BASE_BRANCH":"refs/remotes/origin/${BASE_BRANCH}" || true

# Create new working branch from origin/main (avoid basing on local checked-out branch)
git checkout -b "$BRANCH" "origin/${BASE_BRANCH}" || git checkout -b "$BRANCH"

export GOFLAGS=-mod=mod
export GOPATH="$(go env GOPATH 2>/dev/null || echo "$HOME/go")"
export PATH="$GOPATH/bin:$PATH"

# 1) Update modules to latest (including majors) and bump go directive to latest stable
set -x
go get -u ./... || true
go get go@latest || true
go mod tidy || true
set +x

# Ensure we don't accidentally commit repo-root build artifact
[ -f "./chachacrypt" ] && rm -f ./chachacrypt || true

# Save pre-update diff (allowed-files only)
git add -A
git diff --staged -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true
git restore --staged . || true

# Determine which allowed files changed relative to origin/main
CHANGED_ALLOWED_RAW="$(git diff --name-only origin/${BASE_BRANCH} -- "${ALLOWED_FILES[@]}" || true)"
CHANGED_ALLOWED=()
if [ -n "$CHANGED_ALLOWED_RAW" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] && CHANGED_ALLOWED+=("$f")
  done <<< "$CHANGED_ALLOWED_RAW"
fi

# If none changed, exit with no PR requested (but produce small ai-build.log)
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  echo "No relevant changes in go.mod/go.sum/chachacrypt.go; nothing to commit." > ai-build.log
  set_output branch ""
  set_output create_pr "false"
  exit 0
fi

# Stage exactly the allowed changed files and commit (ensure nothing else staged)
git restore --staged . || true
for f in "${CHANGED_ALLOWED[@]}"; do
  git add -- "$f" || true
done

# Unstage anything not in allowed set (double-check)
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
  echo "No staged changes to commit after filtering allowed files." > ai-build.log
  set_output branch ""
  set_output create_pr "false"
  exit 0
fi

# Push branch to remote (so create-pull-request sees it). Use GH2_TOKEN if available.
if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
  git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
  git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease
else
  # attempt to push with existing origin credentials
  git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease || true
fi

# Save post-update diff for diagnostics
git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Build & test — write logs to ai-build.log; build to /tmp to avoid repo-root artifacts
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
rm -f /tmp/chachacrypt.build || true
set -e

# Run golangci-lint: prefer v2 flags (installed by action), but detect and fallback
if command -v golangci-lint >/dev/null 2>&1; then
  GOLANGCI_VER=$(golangci-lint --version 2>/dev/null || true)
  # prefer v2 flag --output.json.path
  golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null || true
  # attempt fix pass (non-fatal)
  golangci-lint run --fix --timeout=5m ./... || true
else
  echo '{"error":"golangci-lint not installed"}' > ai-lint.json
fi

# staticcheck if available
if command -v staticcheck >/dev/null 2>&1; then
  staticcheck ./... > staticcheck.txt || true
else
  echo "staticcheck not available" > staticcheck.txt
fi

# Copy canonical artifact names (ensure presence)
cp ai-lint.json ai-lint.json 2>/dev/null || true
cp staticcheck.txt ai-staticcheck.txt 2>/dev/null || true
cp "$AI_BUILD_LOG" ai-build.log 2>/dev/null || true
cp ai-lint.json golangci-lint.json 2>/dev/null || true

# Determine whether branch actually differs from origin/main (safety)
AHEAD_COUNT=$(git rev-list --right-only --count "origin/${BASE_BRANCH}...HEAD" 2>/dev/null || true)
if [ -z "$AHEAD_COUNT" ]; then
  AHEAD_COUNT=0
fi

if [ "$AHEAD_COUNT" -gt 0 ]; then
  set_output branch "$BRANCH"
  # if build/test succeeded, request PR; otherwise we may request PR anyway so human can inspect
  if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
    set_output create_pr "true"
    # already pushed earlier
    exit 0
  fi
else
  # no diff vs origin/main; nothing to PR
  set_output branch "$BRANCH"
  set_output create_pr "false"
  exit 0
fi

# If we reached here, branch ahead and build/test failed => attempt AI-assisted fixes (constrained)
if [ -n "$OPENROUTER_API_KEY" ] && { [ "$BUILD_EXIT" -ne 0 ] || [ "$TEST_EXIT" -ne 0 ]; }; then

  # Prepare diagnostics for AI
  DIAGNOSTIC_SUMMARY="ai-diagnostics.txt"
  {
    echo "=== Build & Test Log ==="
    cat ai-build.log 2>/dev/null || true
    echo
    echo "=== golangci-lint JSON ==="
    cat ai-lint.json 2>/dev/null || true
    echo
    echo "=== staticcheck ==="
    cat staticcheck.txt 2>/dev/null || true
  } > "$DIAGNOSTIC_SUMMARY"

  # Truncate to safe sizes
  head -n 4000 ai-diff-after.patch > ai-diff-after.patch.tmp 2>/dev/null || true
  if [ -f ai-diff-after.patch.tmp ]; then mv ai-diff-after.patch.tmp ai-diff-after.patch || true; fi
  head -n 4000 "$DIAGNOSTIC_SUMMARY" > "${DIAGNOSTIC_SUMMARY}.tmp" 2>/dev/null || true
  if [ -f "${DIAGNOSTIC_SUMMARY}.tmp" ]; then mv "${DIAGNOSTIC_SUMMARY}.tmp" "$DIAGNOSTIC_SUMMARY" || true; fi

  # System prompt file for AI
  cat > ai-system-prompt.txt <<'SYS'
You are tngtech/deepseek-r1t2-chimera, an expert Go engineer.
You will be provided:
- ai-diff-after.patch (recent changes to go.mod/go.sum/chachacrypt.go)
- diagnostics with build/test and linter logs.

CONSTRAINT: You MUST ONLY propose edits to go.mod, go.sum, and/or chachacrypt.go.
Return exactly a single unified diff (git apply format) touching only these files,
or the single line: NO_PATCH_POSSIBLE
SYS

  PATCH_CONTENT="$(sed -n '1,200000p' ai-diff-after.patch 2>/dev/null || true)"
  DIAG_CONTENT="$(sed -n '1,200000p' "$DIAGNOSTIC_SUMMARY" 2>/dev/null || true)"

  ITER=0
  while [ "$ITER" -lt "$MAX_ITER" ]; do
    ITER=$((ITER+1))
    RESPONSE_FILE="ai-response-${ITER}.json"

    # Build payload JSON robustly using python to avoid shell-escaping issues
    python3 - <<PY > ai-payload.json
import json,os,sys
model=os.environ.get('MODEL')
system=open('ai-system-prompt.txt','r',encoding='utf-8').read()
patch='''${PATCH_CONTENT}'''
diags='''${DIAG_CONTENT}'''
user_msg = "Patch (ai-diff-after.patch):\\n\\n" + patch + "\\n\\nDiagnostics:\\n\\n" + diags + "\\n\\nPlease produce a single unified patch that modifies only go.mod, go.sum and/or chachacrypt.go. If not possible, reply exactly: NO_PATCH_POSSIBLE"
payload = {
  "model": model,
  "messages": [
    {"role":"system","content": system},
    {"role":"user","content": user_msg}
  ],
  "temperature": 0.0,
  "max_tokens": 32768
}
print(json.dumps(payload))
PY

    # Call OpenRouter
    curl -sS -X POST "${OPENROUTER_ENDPOINT}" \
      -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
      -H "Content-Type: application/json" \
      --data-binary @ai-payload.json -o "${RESPONSE_FILE}" || true

    # Extract patch text using python (robust)
    python3 - <<PY > ai-fix-${ITER}.log
import json,sys
try:
    obj=json.load(open('${RESPONSE_FILE}', 'r', encoding='utf-8'))
    # try to find assistant message content
    text=""
    if isinstance(obj.get("choices"), list) and obj["choices"]:
        ch=obj["choices"][0]
        if isinstance(ch.get("message"), dict):
            text = ch["message"].get("content","") or ch.get("text","")
        else:
            text = ch.get("text","")
    if not text:
        # fallback: try top-level text keys
        text = obj.get("text","")
    print(text)
except Exception as e:
    print("")
PY

    PATCH_TEXT=$(sed -n '1,200000p' "ai-fix-${ITER}.log" 2>/dev/null || true)

    if echo "$PATCH_TEXT" | tr -d '\r' | grep -q '^NO_PATCH_POSSIBLE$'; then
      break
    fi

    # write patch file
    printf "%s\n" "$PATCH_TEXT" > "ai-fix-${ITER}.patch"

    # Validate that the patch only touches allowed files
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

    # Ensure patch cleanly applies
    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      git apply "ai-fix-${ITER}.patch"
      # ensure only allowed files changed; revert others if any
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

      # Stage and commit allowed files only
      for f in "${ALLOWED_FILES[@]}"; do
        if ! git diff --quiet -- "$f" 2>/dev/null; then
          git add -- "$f"
        fi
      done
      git commit -m "chore: ai: apply automated fixes (iteration ${ITER})" || true

      # Push updated branch
      if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
        git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease
      else
        git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease || true
      fi

      # Re-run build & tests and append logs
      set +e
      go build -o /tmp/chachacrypt.build ./... >> ai-build.log 2>&1
      BUILD_EXIT=$?
      go test ./... >> ai-build.log 2>&1
      TEST_EXIT=$?
      rm -f /tmp/chachacrypt.build || true
      set -e

      # Update linter outputs
      if command -v golangci-lint >/dev/null 2>&1; then
        golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null || true
      fi
      if command -v staticcheck >/dev/null 2>&1; then
        staticcheck ./... > ai-staticcheck.txt || true
      fi

      # Check if build/tests now pass
      if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
        break
      else
        # update ai-diff-after.patch for next iteration
        git diff HEAD~1..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true
        continue
      fi
    else
      # patch failed check; try next iteration
      continue
    fi
  done
fi

# Final: decide and emit outputs
# Ensure branch is pushed and determine if branch differs from origin/main
set +e
git fetch origin "${BASE_BRANCH}" --depth=1 || true
AHEAD_COUNT_FINAL=$(git rev-list --right-only --count "origin/${BASE_BRANCH}...HEAD" 2>/dev/null || true)
set -e
if [ -z "$AHEAD_COUNT_FINAL" ]; then
  AHEAD_COUNT_FINAL=0
fi

set_output branch "$BRANCH"
if [ "$AHEAD_COUNT_FINAL" -gt 0 ]; then
  set_output create_pr "true"
else
  set_output create_pr "false"
fi

exit 0
