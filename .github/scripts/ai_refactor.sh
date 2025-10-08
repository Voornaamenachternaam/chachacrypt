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

# Write branch output for workflow
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

# Preflight: ensure we have minimal required envs
if [ -z "$GH2_TOKEN" ]; then
  echo "GH2_TOKEN not provided; script will still run but cannot push PR branch."
fi
if [ -z "$OPENROUTER_API_KEY" ]; then
  echo "OPENROUTER_API_KEY not provided; AI fixes will be skipped."
fi

# Git config
git config user.name "$GIT_USER_NAME"
git config user.email "$GIT_USER_EMAIL"

# Fetch and create working branch
git fetch --all --prune
git checkout -b "$BRANCH"

# Ensure GOFLAGS
export GOFLAGS=-mod=mod

# 1) Update modules to latest (including majors) and bump go directive to latest stable
set -x
# Upgrade all deps to their latest versions (direct + indirect)
go get -u ./... || true
# Bump module 'go' directive to latest stable
go get go@latest || true
# Clean up
go mod tidy || true
set +x

# Ensure no build artifact ends up in repo root: build to temp if needed
# Save pre-update diff for allowed files
git add -A
git diff --staged -- "${ALLOWED_FILES[@]}" > ai-diff-before.patch || true
git reset --quiet

# Identify allowed files that have changes (unstaged)
CHANGED_ALLOWED=()
for f in "${ALLOWED_FILES[@]}"; do
  if git diff --name-only -- "$f" | grep -q '.'; then
    CHANGED_ALLOWED+=( "$f" )
  fi
done

# If none changed, attempt safe automatic linter fixes (do not create commits for other files)
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  if command -v golangci-lint >/dev/null 2>&1; then
    golangci-lint run --fix --timeout=5m ./... || true
  fi
  # recompute
  for f in "${ALLOWED_FILES[@]}"; do
    if git diff --name-only -- "$f" | grep -q '.'; then
      CHANGED_ALLOWED+=( "$f" )
    fi
  done
fi

# If still nothing to change, do not create PR branch
if [ "${#CHANGED_ALLOWED[@]}" -eq 0 ]; then
  BRANCH=""
  exit 0
fi

# Stage only allowed changed files and commit
for f in "${CHANGED_ALLOWED[@]}"; do
  git add "$f" || true
done
git commit -m "chore: update Go toolchain & modules to latest (automated)" || true

# Save post-update diff limited to allowed files
git diff HEAD^..HEAD -- "${ALLOWED_FILES[@]}" > ai-diff-after.patch || true

# Build & Test — write logs (artifacts), but do not create files in repo root
AI_BUILD_LOG="ai-build.log"
: > "$AI_BUILD_LOG"
set +e
# Build to temp output to avoid creating repo-root binaries
go build -o /tmp/chachacrypt.build ./... >> "$AI_BUILD_LOG" 2>&1
BUILD_EXIT=$?
go test ./... >> "$AI_BUILD_LOG" 2>&1
TEST_EXIT=$?
# cleanup temp binary
rm -f /tmp/chachacrypt.build || true
set -e

# Linters: use golangci-lint modern flags
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint --version || true
  golangci-lint run --timeout=5m --output.json.path=golangci-lint.json ./... || true
else
  echo '{"error":"golangci-lint miss
