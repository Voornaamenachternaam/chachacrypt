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
MODEL="${MODEL:-deepseek/deepseek-r1-0528-qwen3-8b:free}"
OPENROUTER_ENDPOINT="${OPENROUTER_ENDPOINT:-https://api.openrouter.ai/v1/chat/completions}"

ALLOWED_FILES=( "go.mod" "go.sum" "chachacrypt.go" )
FALLBACK_BASE_BRANCH="main"

# Write outputs directly to runner-provided file (avoid 'cat temp >> $GITHUB_OUTPUT' pitfalls)
set_output() {
  name="$1"
  value="$2"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_OUTPUT"
  else
    # Local run: print
    printf '%s=%s\n' "$name" "$value"
  fi
}

# Configure git identity
git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

# Determine remote default branch robustly
default_branch=""
if git ls-remote --symref origin HEAD 2>/dev/null | grep -q 'refs/heads/'; then
  default_branch="$(git ls-remote --symref origin HEAD 2>/dev/null | awk '/^ref:/{print $2; exit}' | sed 's@refs/heads/@@')"
fi

# Fallback checks for common names
if [ -z "$default_branch" ]; then
  if git ls-remote --exit-code --heads origin main >/dev/null 2>&1; then
    default_branch="main"
  elif git ls-remote --exit-code --heads origin master >/dev/null 2>&1; then
    default_branch="master"
  else
    default_branch="${FALLBACK_BASE_BRANCH}"
  fi
fi

# Fetch default branch safely (if exists)
git fetch --no-tags --prune origin "+refs/heads/${default_branch}:refs/remotes/origin/${default_branch}" || true

# Create new branch, prefer origin/default_branch as base, else current HEAD
if git rev-parse --verify --quiet "refs/remotes/origin/${default_branch}" >/dev/null 2>&1; then
  git checkout -b "$BRANCH" "origin/${default_branch}"
else
  git checkout -b "$BRANCH"
fi

export GOFLAGS=-mod=mod
export GOPATH="$(go env GOPATH 2>/dev/null || echo "$HOME/go")"
export PATH="$GOPATH/bin:$PATH"

# 1) Update go directive to latest toolchain, then update modules
set -x
# First, update the go directive in go.mod to match the available toolchain.
GO_VERSION_STRING=$(go version | awk '{print $3}' | sed 's/go//' 2>/dev/null)
if [ -n "$GO_VERSION_STRING" ]; then
  go mod tidy -go="$GO_VERSION_STRING" || true
fi

# Second, update all module dependencies to their latest versions.
go get -u ./... || true

# Finally, run tidy again to clean up any unused module requirements.
go mod tidy || true
set +x

# Ensure no repo-root binary is left behind
[ -f "./chachacrypt" ] && rm -f ./chachacrypt || true

# Save a pre-update patch for diagnostics (allowed-files only)
git add -A
git diff --staged -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true
git restore --staged . || true

# Compute which allowed files changed relative to origin/default_branch
CHANGED_RAW="$(git diff --name-only "origin/${default_branch}" -- "${ALLOWED_FILES[@]}" 2>/dev/null || true)"
CHANGED_ALLOWED=()
if [ -n "$CHANGED_RAW" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] && CHANGED_ALLOWED+=("$f")
  done <<< "$CHANGED_RAW"
fi

# If no allowed-file changes, produce artifact and exit (no PR)
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  echo "No changes to go.mod/go.sum/chachacrypt.go after module updates." > ai-build.log
  set_output branch ""
  set_output create_pr "false"
  exit 0
fi

# Stage exactly allowed changed files
git restore --staged . || true
for f in "${CHANGED_ALLOWED[@]}"; do
  git add -- "$f" || true
done

# Unstage anything else, just to be sure
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

# Commit allowed files only
if ! git diff --cached --quiet; then
  git commit -m "chore: update Go toolchain & modules to latest (automated)" || true
else
  echo "Nothing to commit after filtering allowed files." > ai-build.log
  set_output branch ""
  set_output create_pr "false"
  exit 0
fi

# Save post-update diff
git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Build & test (logs to ai-build.log); build to /tmp to avoid repo-root executables
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
rm -f /tmp/chachacrypt.build || true
set -e

# Try to ensure golangci-lint output is produced (v2 prefers --output.json.path)
if command -v golangci-lint >/dev/null 2>&1; then
  set +e
  golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... 2>/dev/null
  rc=$?
  if [ "$rc" -ne 0 ]; then
    # fallback to older flag forms (if the binary supports them)
    golangci-lint run --timeout=5m --out-format json ./... > ai-lint.json 2>/dev/null || true
  fi
  # attempt an automatic fix pass (non-fatal)
  golangci-lint run --fix --timeout=5m ./... || true
  set -e
else
  echo '{"error":"golangci-lint not installed"}' > ai-lint.json
fi

# staticcheck
if command -v staticcheck >/dev/null 2>&1; then
  staticcheck ./... > staticcheck.txt || true
else
  echo "staticcheck not available" > staticcheck.txt
fi

# Ensure canonical artifact names exist
cp ai-lint.json ai-lint.json 2>/dev/null || true
cp staticcheck.txt ai-staticcheck.txt 2>/dev/null || true
cp "$AI_BUILD_LOG" ai-build.log 2>/dev/null || true
cp ai-lint.json golangci-lint.json 2>/dev/null || true

# Push new branch to remote (so create-pull-request can act on it)
if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
  git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
  git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease
else
  git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease || true
fi

# Determine whether branch differs from origin/default_branch
git fetch origin "${default_branch}" --depth=1 || true
AHEAD_COUNT=$(git rev-list --right-only --count "origin/${default_branch}...HEAD" 2>/dev/null || true)
AHEAD_COUNT="${AHEAD_COUNT:-0}"

set_output branch "$BRANCH"
# If branch ahead of base, request PR. Otherwise don't.
if [ "$AHEAD_COUNT" -gt 0 ]; then
  set_output create_pr "true"
else
  set_output create_pr "false"
fi

# If build/tests failed and OPENROUTER_API_KEY provided, attempt AI-assisted fixes constrained to allowed files
if { [ "$BUILD_EXIT" -ne 0 ] || [ "$TEST_EXIT" -ne 0 ]; } && [ -n "$OPENROUTER_API_KEY" ]; then
  DIAG="ai-diagnostics.txt"
  {
    echo "=== Build & Test Log ==="
    cat ai-build.log 2>/dev/null || true
    echo
    echo "=== golangci-lint JSON ==="
    cat ai-lint.json 2>/dev/null || true
    echo
    echo "=== staticcheck ==="
    cat staticcheck.txt 2>/dev/null || true
  } > "$DIAG"

  # Truncate large artifacts
  head -n 4000 ai-diff-after.patch > ai-diff-after.patch.tmp 2>/dev/null || true
  if [ -f ai-diff-after.patch.tmp ]; then mv ai-diff-after.patch.tmp ai-diff-after.patch || true; fi
  head -n 4000 "$DIAG" > "${DIAG}.tmp" 2>/dev/null || true
  if [ -f "${DIAG}.tmp" ]; then mv "${DIAG}.tmp" "$DIAG" || true; fi

  # Compose AI request payload via Python (robust quoting)
  PATCH_CONTENT="$(sed -n '1,200000p' ai-diff-after.patch 2>/dev/null || true)"
  DIAG_CONTENT="$(sed -n '1,200000p' "$DIAG" 2>/dev/null || true)"

  ITER=0
  while [ "$ITER" -lt "$MAX_ITER" ]; do
    ITER=$((ITER+1))
    RESPONSE_FILE="ai-response-${ITER}.json"

    python3 - <<PY > ai-payload.json
import json,os
payload = {
  "model": os.environ.get("MODEL", "${MODEL}"),
  "messages": [
    {"role":"system","content": "You are tngtech/deepseek-r1t2-chimera, an expert Go engineer. You will be given ai-diff-after.patch and diagnostics. CONSTRAINT: You MUST ONLY propose edits to go.mod, go.sum, and/or chachacrypt.go. Return exactly one unified diff (git apply format) touching only these files, or the single line: NO_PATCH_POSSIBLE."},
    {"role":"user","content": "Patch (ai-diff-after.patch):\\n\\n" + '''${PATCH_CONTENT}''' + "\\n\\nDiagnostics:\\n\\n" + '''${DIAG_CONTENT}''' + "\\n\\nPlease produce a single unified patch that modifies only go.mod, go.sum and/or chachacrypt.go. If not possible, reply exactly: NO_PATCH_POSSIBLE"}
  ],
  "temperature": 0.0,
  "max_tokens": 32768
}
print(json.dumps(payload))
PY

    curl -sS -X POST "${OPENROUTER_ENDPOINT}" \
      -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
      -H "Content-Type: application/json" \
      --data-binary @ai-payload.json -o "${RESPONSE_FILE}" || true

    # extract assistant text robustly
    python3 - <<PY > ai-fix-${ITER}.log
import json,sys
try:
    obj=json.load(open("${RESPONSE_FILE}","r",encoding="utf-8"))
    text=""
    if isinstance(obj.get("choices"), list) and obj["choices"]:
        ch=obj["choices"][0]
        if isinstance(ch.get("message"), dict):
            text = ch["message"].get("content","") or ch.get("text","")
        else:
            text = ch.get("text","")
    print(text or "")
except Exception:
    print("")
PY

    PATCH_TEXT="$(sed -n '1,200000p' ai-fix-${ITER}.log 2>/dev/null || true)"
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

    # Check application and apply
    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      git apply "ai-fix-${ITER}.patch"
      # Revert any non-allowed changes
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
          git add -- "$f"
        fi
      done
      git commit -m "chore: ai: apply automated fixes (iteration ${ITER})" || true

      # Push updated branch
      if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
        git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
      fi
      git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease || true

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

      # If fixed, break; otherwise continue next iteration
      if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
        break
      else
        git diff HEAD~1..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true
        continue
      fi
    else
      # patch can't apply; try next iteration
      continue
    fi
  done
fi

# Final outputs: ensure branch pushed and whether PR should be created
git fetch origin "${default_branch}" --depth=1 || true
AHEAD_FINAL=$(git rev-list --right-only --count "origin/${default_branch}...HEAD" 2>/dev/null || true)
AHEAD_FINAL="${AHEAD_FINAL:-0}"

set_output branch "$BRANCH"
if [ "$AHEAD_FINAL" -gt 0 ]; then
  set_output create_pr "true"
else
  set_output create_pr "false"
fi

exit 0
