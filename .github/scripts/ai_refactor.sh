#!/usr/bin/env bash
set -euo pipefail

# ai_refactor.sh
# Automated AI-powered refactoring script for Go projects.
# Usage:
#   ./ai_refactor.sh <go-version|dependencies> <api-url>
#
# Requirements:
# - OPENROUTER_API_KEY environment variable set (GitHub secret)
# - AI_MODEL environment variable set (e.g. deepseek/deepseek-r1:free)
# - curl and jq available (script will attempt to install jq if missing on Debian-based runners)
# - git available (used to commit changes so the create-pull-request step can pick them up)

# --- Argument validation ---
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <go-version|dependencies> <api-url>"
  exit 1
fi

REFACTOR_TYPE=$1
API_URL=$2

# --- Environment validation ---
if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "Error: OPENROUTER_API_KEY environment variable is not set. Exiting."
  exit 1
fi

if [ -z "${AI_MODEL:-}" ]; then
  echo "Error: AI_MODEL environment variable is not set. Exiting."
  exit 1
fi

# --- Ensure required CLI tools are present ---
command -v curl >/dev/null 2>&1 || { echo "Error: curl is required but not installed. Exiting."; exit 1; }
if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "jq not found. Attempting to install jq using apt-get..."
    sudo apt-get update -y
    sudo apt-get install -y jq
  else
    echo "Error: jq is required but not installed and cannot be installed automatically on this runner. Exiting."
    exit 1
  fi
fi

echo "Starting AI-powered refactoring: type='${REFACTOR_TYPE}' api='${API_URL}' model='${AI_MODEL}'"

# --- Discover Go source files (exclude vendor and tests) ---
# Use readarray to preserve filenames with spaces
readarray -t GO_FILES < <(find . -type f -name "*.go" -not -path "./vendor/*" -not -name "*_test.go" -print)

if [ "${#GO_FILES[@]}" -eq 0 ]; then
  echo "No Go source files found to refactor. Exiting."
  exit 0
fi

# Helper: strip surrounding triple-backticks and leading language marker
strip_code_fences() {
  # Removes leading ```lang and trailing ``` if present, preserving content inside.
  sed -e '1s/^```[[:alnum:]]*[\r\n]*//' -e '${/^```$/d}' -e 's/\r$//' | sed '/^```$/d'
}

# Ensure git user config for automated commits
git config user.name "github-actions[bot]" || true
git config user.email "github-actions[bot]@users.noreply.github.com" || true

TMPDIR=$(mktemp -d)
cleanup() {
  rm -rf "${TMPDIR}"
}
trap cleanup EXIT

# Iterate files
for file in "${GO_FILES[@]}"; do
  echo "Processing file: ${file}"

  # Build prompt
  file_content=$(sed -n '1,20000p' "${file}" || true)
  PROMPT=$(cat <<EOF
You are an expert Go developer. I have recently updated a ${REFACTOR_TYPE} which may have introduced breaking changes in the following file: ${file}.

Your task is to provide a complete, ready-to-write Go source file that resolves compilation errors, breaking changes, and deprecated function calls introduced by the ${REFACTOR_TYPE} change while preserving original functionality and intent. Provide idiomatic, modern Go. Do not include explanations — only a single code block containing the complete file contents (no surrounding commentary). If no changes are required, return the original file contents verbatim.

File path: ${file}

Code to refactor:
\`\`\`go
${file_content}
\`\`\`
EOF
)

  # Build JSON payload using jq to ensure proper escaping
  JSON_PAYLOAD=$(jq -n \
    --arg model "$AI_MODEL" \
    --arg content "$PROMPT" \
    '{
      model: $model,
      messages: [
        { role: "user", content: $content }
      ],
      temperature: 0.0,
      max_tokens: 2000
    }'
  )

  # Call API and extract the response content
  RESPONSE_RAW="$TMPDIR/response.json"
  set +e
  curl --silent --show-error --location --fail --request POST "${API_URL}" \
    --header "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    --header "Content-Type: application/json" \
    --data "${JSON_PAYLOAD}" > "${RESPONSE_RAW}"
  CURL_EXIT=$?
  set -e

  if [ "${CURL_EXIT}" -ne 0 ]; then
    echo "Error: curl failed for file ${file} (exit ${CURL_EXIT}). Skipping."
    continue
  fi

  # Extract content field defensively (supporting OpenRouter's chat completions schema)
  AI_RESPONSE=$(jq -r '.choices[0].message.content // .choices[0].text // ""' "${RESPONSE_RAW}" 2>/dev/null || true)

  if [ -z "${AI_RESPONSE}" ] || [ "${AI_RESPONSE}" = "null" ]; then
    echo "Warning: AI response was empty or could not be parsed for file ${file}. Skipping."
    continue
  fi

  # Clean code fences if present
  CLEANED_RESPONSE=$(printf "%s" "${AI_RESPONSE}" | strip_code_fences)

  # Sanity check: ensure output contains "package " for Go files to reduce risk of accidental garbage
  if ! printf "%s" "${CLEANED_RESPONSE}" | grep -q '^package[[:space:]]' ; then
    echo "Warning: AI output for ${file} does not appear to be a complete Go file (missing package declaration). Skipping."
    continue
  fi

  # Write to temporary file then format with gofmt before replacing original
  OUT_TMP="${TMPDIR}/out.go"
  printf "%s\n" "${CLEANED_RESPONSE}" > "${OUT_TMP}"
  # Attempt to format; if gofmt fails, skip to avoid corrupting file
  if command -v gofmt >/dev/null 2>&1; then
    if ! gofmt -w "${OUT_TMP}"; then
      echo "Warning: gofmt failed for ${file}. Skipping write to file."
      continue
    fi
  fi

  # If the content is identical to existing file, skip
  if cmp -s "${OUT_TMP}" "${file}"; then
    echo "No changes required for ${file}."
    continue
  fi

  # Replace original file with refactored content
  mv "${OUT_TMP}" "${file}"
  git add -- "${file}"

  # Commit the change for the file (will be collected by create-pull-request action later)
  if git diff --cached --quiet --exit-code; then
    echo "No staged changes to commit for ${file}."
  else
    COMMIT_MSG="chore(ai): refactor ${file} for ${REFACTOR_TYPE} (AI: ${AI_MODEL})"
    git commit -m "${COMMIT_MSG}" || true
    echo "Committed changes for ${file}."
  fi

done

echo "AI-powered refactoring completed successfully."
exit 0
