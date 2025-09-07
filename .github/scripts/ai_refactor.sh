#!/usr/bin/env bash
set -euo pipefail

# ai_refactor.sh
# Usage:
#   ./ai_refactor.sh <go-version|dependencies> <api-url>
#
# Requirements:
# - OPENROUTER_API_KEY environment variable set (GitHub secret)
# - AI_MODEL environment variable set (e.g. deepseek/deepseek-r1:free)
# - curl and jq available (script will attempt to install jq on Debian-based runners)
# - git available (used to commit changes)

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <go-version|dependencies> <api-url>"
  exit 1
fi

REFACTOR_TYPE=$1
API_URL=$2

if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "Error: OPENROUTER_API_KEY environment variable is not set. Exiting."
  exit 1
fi

if [ -z "${AI_MODEL:-}" ]; then
  echo "Error: AI_MODEL environment variable is not set. Exiting."
  exit 1
fi

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

# Find Go files (exclude vendor and test files)
readarray -t GO_FILES < <(find . -type f -name "*.go" -not -path "./vendor/*" -not -name "*_test.go" -print)

if [ "${#GO_FILES[@]}" -eq 0 ]; then
  echo "No Go source files found to refactor. Exiting."
  exit 0
fi

git config user.name "github-actions[bot]" || true
git config user.email "github-actions[bot]@users.noreply.github.com" || true

TMPDIR=$(mktemp -d)
cleanup() {
  rm -rf "${TMPDIR}"
}
trap cleanup EXIT

# Helper: extract first code block marked with ``` or return original text if none.
extract_code_block() {
  awk '
    BEGIN { inblock=0; first=1 }
    /^```/ {
      if (inblock==0) { inblock=1; next }
      else { inblock=0; exit }
    }
    inblock { print }
    END { if (first && NR==0) {} }
  ' || true
}

# Helper: attempt to send prompt to API and parse response; supports retries for empty responses
call_ai_api() {
  local payload="$1"
  local outfile="$2"
  local attempts=0
  local max_attempts=2
  while [ $attempts -lt $max_attempts ]; do
    attempts=$((attempts+1))
    set +e
    curl --silent --show-error --location --fail --request POST "${API_URL}" \
      --header "Authorization: Bearer ${OPENROUTER_API_KEY}" \
      --header "Content-Type: application/json" \
      --data "${payload}" > "${outfile}"
    CURL_EXIT=$?
    set -e
    if [ "${CURL_EXIT}" -ne 0 ]; then
      echo "Warning: curl attempt ${attempts} failed (exit ${CURL_EXIT})."
      if [ $attempts -lt $max_attempts ]; then
        sleep 1
        continue
      else
        return 1
      fi
    fi

    # Try multiple common response fields (OpenRouter may vary)
    AI_CONTENT=$(jq -r '.choices[0].message.content // .choices[0].text // .output[0].content // ""' "${outfile}" 2>/dev/null || true)
    if [ -n "${AI_CONTENT}" ] && [ "${AI_CONTENT}" != "null" ]; then
      printf '%s' "${AI_CONTENT}" > "${outfile}.content"
      return 0
    fi

    # If empty, attempt again (up to max_attempts)
    echo "Warning: AI returned empty content on attempt ${attempts}."
    if [ $attempts -lt $max_attempts ]; then
      sleep 1
      continue
    fi
    return 2
  done
}

for file in "${GO_FILES[@]}"; do
  echo "Processing file: ${file}"
  # Read file content safely
  file_content=$(cat "${file}" || true)

  PROMPT=$(printf '%s\n' "You are an expert Go developer. I have recently updated a ${REFACTOR_TYPE} which may have introduced breaking changes in the following file: ${file}.
Your task is to provide a complete, ready-to-write Go source file that resolves compilation errors, breaking changes, and deprecated function calls introduced by the ${REFACTOR_TYPE} change while preserving original functionality and intent. Provide idiomatic, modern Go. Return only a single code block (```go ... ```) or the complete file contents with no extra commentary.

File path: ${file}

Code to refactor:
\`\`\`go
${file_content}
\`\`\`")

  JSON_PAYLOAD=$(jq -n \
    --arg model "${AI_MODEL}" \
    --arg content "${PROMPT}" \
    '{
      model: $model,
      messages: [ { role: "user", content: $content } ],
      temperature: 0.0,
      max_tokens: 2000
    }'
  )

  RESPONSE_RAW="${TMPDIR}/response.json"
  if ! call_ai_api "${JSON_PAYLOAD}" "${RESPONSE_RAW}"; then
    echo "Warning: AI call failed or returned empty for ${file}. Skipping."
    continue
  fi

  AI_RESPONSE=$(cat "${RESPONSE_RAW}.content" || true)

  # Extract code inside first triple-backtick block if present, otherwise use entire response
  CLEANED_RESPONSE=$(printf "%s" "${AI_RESPONSE}" | awk '
    BEGIN { in=0; printed=0 }
    /^```/ {
      if (in==0) { in=1; next } else { in=0; exit }
    }
    in { print; printed=1 }
    END { if (printed==0) { exit 2 } }' || true)

  if [ -z "${CLEANED_RESPONSE}" ]; then
    # No fenced block found; use raw response
    CLEANED_RESPONSE="${AI_RESPONSE}"
  fi

  # Strip potential leading/trailing windows line endings
  CLEANED_RESPONSE=$(printf "%s" "${CLEANED_RESPONSE}" | sed 's/\r$//')

  # Quick sanity: ensure package declaration present
  if ! printf "%s" "${CLEANED_RESPONSE}" | grep -q '^package[[:space:]]' ; then
    echo "Warning: AI output for ${file} does not appear to be a complete Go file (missing package declaration). Skipping."
    # Save the raw AI output for debugging
    printf "%s\n" "${AI_RESPONSE}" > "${TMPDIR}/bad_response_$(basename "${file}").txt"
    continue
  fi

  # Write to temporary output file
  OUT_TMP="${TMPDIR}/out.go"
  printf "%s\n" "${CLEANED_RESPONSE}" > "${OUT_TMP}"

  # Attempt to format; if gofmt fails, capture error and attempt a single automated retry with the AI to fix syntax errors
  if command -v gofmt >/dev/null 2>&1; then
    if ! gofmt -w "${OUT_TMP}" 2> "${TMPDIR}/gofmt.err"; then
      GOFMT_ERR=$(cat "${TMPDIR}/gofmt.err" || true)
      echo "gofmt reported errors for ${file}:"
      printf '%s\n' "${GOFMT_ERR}"
      # Prepare a follow-up prompt to fix syntax errors
      FIX_PROMPT=$(printf '%s\n' "The previously returned refactored Go file for ${file} contains syntax/formatting errors reported by gofmt:

gofmt errors:
${GOFMT_ERR}

Here is the refactored file content that produced those errors:
\`\`\`go
${CLEANED_RESPONSE}
\`\`\`

Please return a corrected, fully compilable Go source file that resolves the gofmt errors and any syntax issues. Return only the complete file contents (no commentary), optionally as a single ```go code block or plain file content.")

      JSON_PAYLOAD_FIX=$(jq -n \
        --arg model "${AI_MODEL}" \
        --arg content "${FIX_PROMPT}" \
        '{
          model: $model,
          messages: [ { role: "user", content: $content } ],
          temperature: 0.0,
          max_tokens: 2000
        }'
      )

      RESPONSE_FIXED_RAW="${TMPDIR}/response_fixed.json"
      if call_ai_api "${JSON_PAYLOAD_FIX}" "${RESPONSE_FIXED_RAW}"; then
        AI_RESPONSE_FIXED=$(cat "${RESPONSE_FIXED_RAW}.content" || true)
        CLEANED_FIXED=$(printf "%s" "${AI_RESPONSE_FIXED}" | awk '
          BEGIN { in=0; printed=0 }
          /^```/ {
            if (in==0) { in=1; next } else { in=0; exit }
          }
          in { print; printed=1 }
          END { if (printed==0) { exit 2 } }' || true)
        if [ -z "${CLEANED_FIXED}" ]; then
          CLEANED_FIXED="${AI_RESPONSE_FIXED}"
        fi
        CLEANED_FIXED=$(printf "%s" "${CLEANED_FIXED}" | sed 's/\r$//')
        printf "%s\n" "${CLEANED_FIXED}" > "${OUT_TMP}"
        # Try formatting again
        if command -v gofmt >/dev/null 2>&1 && ! gofmt -w "${OUT_TMP}" 2> "${TMPDIR}/gofmt2.err"; then
          echo "Warning: gofmt still fails after AI fix for ${file}. Skipping file and saving diagnostics."
          cat "${TMPDIR}/gofmt2.err" || true
          printf "%s\n" "${AI_RESPONSE_FIXED}" > "${TMPDIR}/bad_response_fixed_$(basename "${file}").txt"
          continue
        fi
      else
        echo "Warning: Follow-up AI attempt to fix syntax failed for ${file}. Skipping."
        continue
      fi
    fi
  fi

  # If formatting succeeded, compare with existing file
  if cmp -s "${OUT_TMP}" "${file}"; then
    echo "No changes required for ${file}."
    continue
  fi

  # Replace original file with refactored content
  mv "${OUT_TMP}" "${file}"
  git add -- "${file}"

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
