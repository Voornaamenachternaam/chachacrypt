#!/usr/bin/env bash
set -euo pipefail

# ai_refactor.sh
# Usage:
#   ./ai_refactor.sh <go-version|dependencies> <api-url>
# Environment:
#   OPENROUTER_API_KEY - required
#   AI_MODEL - required (e.g. deepseek/deepseek-r1:free)

REFACTOR_TYPE="${1:-}" || true
API_URL="${2:-}" || true

function die() {
  echo "Error: $*" >&2
  exit 1
}

# Validate args
if [ -z "${REFACTOR_TYPE}" ]; then
  die "Missing refactor type. Usage: $0 <go-version|dependencies> <api-url>"
fi
if [ -z "${API_URL}" ]; then
  die "Missing API URL. Usage: $0 <go-version|dependencies> <api-url>"
fi

# Validate env
if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  die "OPENROUTER_API_KEY environment variable is not set. Exiting."
fi
if [ -z "${AI_MODEL:-}" ]; then
  die "AI_MODEL environment variable is not set. Exiting."
fi

# Ensure required tools: curl, jq, git
command -v curl >/dev/null 2>&1 || die "curl is required but not installed"
if ! command -v jq >/dev/null 2>&1; then
  echo "jq not found. Attempting to install (apt-get)..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y jq || die "Failed to install jq"
  else
    die "jq is required but not found. Please install jq or add it to PATH."
  fi
fi
command -v git >/dev/null 2>&1 || die "git is required but not installed"

# Find go files tracked by git
mapfile -t GO_FILES < <(git ls-files '*.go' || true)
if [ ${#GO_FILES[@]} -eq 0 ]; then
  echo "No .go files found in the repository. Exiting successfully."
  exit 0
fi

# Helper: call OpenRouter with payload
function call_openrouter() {
  local payload_json="$1"
  local max_attempts=3
  local attempt=0
  while [ $attempt -lt $max_attempts ]; do
    attempt=$((attempt+1))
    http_code=$(curl -sS -w "%{http_code}" -o /tmp/ai_response.$$ \
      -X POST "$API_URL" \
      -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
      -H "Content-Type: application/json" \
      -d "$payload_json" ) || true

    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
      cat /tmp/ai_response.$$
      rm -f /tmp/ai_response.$$
      return 0
    fi

    echo "OpenRouter call failed (HTTP ${http_code}), attempt ${attempt}/${max_attempts}."
    if [ $attempt -lt $max_attempts ]; then
      sleep $((attempt * 2))
    else
      cat /tmp/ai_response.$$ || true
      rm -f /tmp/ai_response.$$
      return 2
    fi
  done
}

# Build a robust prompt
function build_prompt() {
  local file_path="$1"
  local change_type="$2"
  local file_content
  file_content=$(sed -n '1,400p' "$file_path" | sed 's/\"/\\\\\"/g' | sed 's/$/\\\\n/')

  jq -n --arg file "$file_path" --arg type "$change_type" --arg content "$file_content" '
  {
    model: $ARGS.named.model,
    messages: [
      {role: "system", content: "You are an expert Go developer. Produce a complete ready-to-write Go source file or precise edits that fix compatibility issues introduced by dependency or go-version changes. Keep semantics, comments and licensing intact where possible. Provide only the updated file contents in a JSON object with keys \"path\" and \"content\". If multiple files require edits, return a JSON array."},
      {role: "user", content: ("Refactor type: " + $type + "\nFile path: " + $file + "\nFile content:\n" + $content)}
    ]
  }' --arg model "$AI_MODEL"
}

TMP_CHANGES_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_CHANGES_DIR}"' EXIT

echo "Starting AI-powered refactoring: type='${REFACTOR_TYPE}' api='${API_URL}' model='${AI_MODEL}'"

modified_any=false
for file in "${GO_FILES[@]}"; do
  echo "Processing file: ${file}"
  payload=$(build_prompt "$file" "$REFACTOR_TYPE")

  ai_output=$(call_openrouter "$payload") || {
    echo "AI call failed for ${file}. Skipping file."
    continue
  }

  if echo "$ai_output" | jq -e . >/dev/null 2>&1; then
    echo "$ai_output" | jq -c '. as $in | (if type=="array" then .[] else . end) | {path: .path, content: .content}' | while IFS= read -r entry; do
      path=$(echo "$entry" | jq -r '.path')
      content=$(echo "$entry" | jq -r '.content')
      if [ -z "$path" ] || [ "$path" = "null" ]; then
        echo "AI result missing path; skipping."
        continue
      fi
      echo "Applying AI edit to ${path}"
      mkdir -p "$(dirname "$path")"
      printf '%s' "$content" > "$path"
      modified_any=true
    done
  else
    echo "AI returned non-JSON output for ${file}. Skipping."
    continue
  fi
done

if [ "$modified_any" = true ]; then
  echo "Committing changes"
  git add -A
  if [ -n "$(git status --porcelain)" ]; then
    git commit -m "chore(ai): apply AI-assisted refactors for ${REFACTOR_TYPE}"
  else
    echo "No changes to commit."
  fi
else
  echo "No modifications detected by AI run."
fi

exit 0
 
