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

# Safe helper to set outputs for GitHub Actions runner (append directly to $GITHUB_OUTPUT)
set_output() {
  name="$1"
  value="$2"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_OUTPUT"
  else
    # local debugging: emit to stdout
    printf '%s=%s\n' "$name" "$value"
  fi
}

# Configure git
git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

# Ensure remote refs available and determine remote default branch robustly
git remote set-url origin "$(git config --get remote.origin.url 2>/dev/null || echo "")" || true
# Try symref HEAD to get default branch
default_ref="$(git ls-remote --symref origin HEAD 2>/dev/null | awk '/^ref:/{print $2; exit}' || true)"
if [ -n "$default_ref" ]; then
  default_branch="${default_ref#refs/heads/}"
else
  # fallback: probe common branch names (main, master) or use env
  if git ls-remote --exit-code --heads origin main >/dev/null 2>&1; then
    default_branch="main"
  elif git ls-remote --exit-code --heads origin master >/dev/null 2>&1; then
    default_branch="master"
  else
    # last fallback: try GITHUB_REF or assume main
    if [ -n "${GITHUB_REF:-}" ]; then
      default_branch="${GITHUB_REF#refs/heads/}"
    else
      default_branch="main"
    fi
  fi
fi

# Fetch and ensure we have the default branch from origin
git fetch origin "+refs/heads/${default_branch}:refs/remotes/origin/${default_branch}" --no-tags --prune || true

# Create a new branch based on remote default branch (safe)
if git rev-parse --verify --quiet "refs/remotes/origin/${default_branch}" >/dev/null 2>&1; then
  git checkout -b "$BRANCH" "origin/${default_branch}"
else
  # fallback to creating branch from current HEAD
  git checkout -b "$BRANCH"
fi

export GOFLAGS=-mod=mod
export GOPATH="$(go env GOPATH 2>/dev/null || echo "$HOME/go")"
export PATH="$GOPATH/bin:$PATH"

# 1) Update modules (including majors) and update go directive using go tool
set -x
go get -u ./... || true
go get go@latest || true
go mod tidy || true
set +x

# Prevent repo-root build binary from being staged
[ -f "./chachacrypt" ] && rm -f ./chachacrypt || true

# Save pre-update diff for allowed files (diagnostics)
git add -A
git diff --staged -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true
git restore --staged . || true

# Determine allowed-file changes relative to origin/default_branch
CHANGED_RAW="$(git diff --name-only origin/${default_branch} -- "${ALLOWED_FILES[@]}" 2>/dev/null || true)"
CHANGED_ALLOWED=()
if [ -n "$CHANGED_RAW" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] && CHANGED_ALLOWED+=("$f")
  done <<< "$CHANGED_RAW"
fi

# If nothing changed, produce artifact and exit (no PR)
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

# Ensure nothing else staged
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

# Build and test; write logs; build to /tmp to avoid repo-root executables
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
rm -f /tmp/chachacrypt.build || true
set -e

# Run golangci-lint (v2.5.0 installed by action). use --output.json.path
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || true
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

# Ensure artifact names exist
cp ai-lint.json ai-lint.json 2>/dev/null || true
cp staticcheck.txt ai-staticcheck.txt 2>/dev/null || true
cp "$AI_BUILD_LOG" ai-build.log 2>/dev/null || true
cp ai-lint.json golangci-lint.json 2>/dev/null || true

# Push branch to remote (so create-pull-request sees it)
if [ -n "$GH2_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ]; then
  git remote set-url origin "https://x-access-token:${GH2_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
  git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease
else
  git push --set-upstream "$GIT_PUSH_REMOTE" "$BRANCH" --force-with-lease || true
fi

# Decide whether branch differs from origin/default_branch
git fetch origin "${default_branch}" --depth=1 || true
AHEAD=$(git rev-list --right-only --count "origin/${default_branch}...HEAD" 2>/dev/null || true)
if [ -z "$AHEAD" ]; then
  AHEAD=0
fi

if [ "$AHEAD" -gt 0 ]; then
  set_output branch "$BRANCH"
  # If build/tests passed, request PR
  if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
    set_output create_pr "true"
    exit 0
  fi
else
  # Branch has no differences -> nothing to PR
  set_output branch "$BRANCH"
  set_output create_pr "false"
  exit 0
fi

# If here: branch differs and build/test failed -> attempt AI-assisted fixes (constrained)
if [ -n "$OPENROUTER_API_KEY" ] && { [ "$BUILD_EXIT" -ne 0 ] || [ "$TEST_EXIT" -ne 0 ]; }; then

  DIAGNOSTIC_SUMMARY="ai-diagnostics.txt"
  {
    echo "=== Build & Test Log ==="
    cat ai-build.log 2>/dev/null || true
    echo
    echo "=== golangci-lint ==="
    cat ai-lint.json 2>/dev/null || true
    echo
    echo "=== staticcheck ==="
    cat staticcheck.txt 2>/dev/null || true
  } > "$DIAGNOSTIC_SUMMARY"

  # truncate to safe size
  head -n 4000 ai-diff-after.patch > ai-diff-after.patch.tmp 2>/dev/null || true
  if [ -f ai-diff-after.patch.tmp ]; then mv ai-diff-after.patch.tmp ai-diff-after.patch || true; fi
  head -n 4000 "$DIAGNOSTIC_SUMMARY" > "${DIAGNOSTIC_SUMMARY}.tmp" 2>/dev/null || true
  if [ -f "${DIAGNOSTIC_SUMMARY}.tmp" ]; then mv "${DIAGNOSTIC_SUMMARY}.tmp" "$DIAGNOSTIC_SUMMARY" || true; fi

  # Prepare system prompt and payload robustly (use python to avoid shell escaping pitfalls)
  cat > ai-system-prompt.txt <<'SYS'
You are tngtech/deepseek-r1t2-chimera, an expert Go engineer.
You will be provided:
- ai-diff-after.patch (recent changes to go.mod/go.sum/chachacrypt.go)
- diagnostics (build/test logs, linter outputs)

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

    python3 - <<PY > ai-payload.json
import json,os
payload = {
  "model": os.environ.get("MODEL", "${MODEL}"),
  "messages": [
    {"role":"system","content": open("ai-system-prompt.txt","r",encoding="utf-8").read()},
    {"role":"user","content": "Patch (ai-diff-after.patch):\\n\\n" + """${PATCH_CONTENT}""" + "\\n\\nDiagnostics:\\n\\n" + """${DIAG_CONTENT}""" + "\\n\\nPlease produce a single unified patch that modifies only go.mod, go.sum and/or chachacrypt.go. If not possible, reply exactly: NO_PATCH_POSSIBLE"}
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

    # extract assistant content robustly
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

    # Check applyability
    if git apply --check "ai-fix-${ITER}.patch" >/dev/null 2>&1; then
      git apply "ai-fix-${ITER}.patch"
      # ensure only allowed files changed; revert any others
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
        golangci-lint run --timeout=5m --output.json.path=ai-lint.json ./... || true
      fi
      if command -v staticcheck >/dev/null 2>&1; then
        staticcheck ./... > ai-staticcheck.txt || true
      fi

      # If fixed, break
      if [ "$BUILD_EXIT" -eq 0 ] && [ "$TEST_EXIT" -eq 0 ]; then
        break
      else
        # refresh ai-diff-after.patch for next iteration
        git diff HEAD~1..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true
        continue
      fi
    else
      continue
    fi
  done
fi

# Final outputs: ensure branch is pushed and whether PR should be created
git fetch origin "${default_branch}" --depth=1 || true
AHEAD_FINAL=$(git rev-list --right-only --count "origin/${default_branch}...HEAD" 2>/dev/null || true)
if [ -z "$AHEAD_FINAL" ]; then
  AHEAD_FINAL=0
fi

set_output branch "$BRANCH"
if [ "$AHEAD_FINAL" -gt 0 ]; then
  set_output create_pr "true"
else
  set_output create_pr "false"
fi

exit 0
