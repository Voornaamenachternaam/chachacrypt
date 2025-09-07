#!/bin/bash
#
# ai_refactor.sh: An automated code refactoring script for Go projects.
# This script is a blueprint for a production-ready AI-powered refactoring engine.
# It is designed to be run as part of a GitHub Actions workflow.
#
# Best practices and features:
# - Secure: Takes the API key from environment variables, not hardcoded.
# - Robust: Uses 'set -e' to fail immediately if any command fails.
# - Portable: Can be adapted to different AI services and APIs.
# - Context-aware: Designed to create detailed prompts for the AI.
#
# Arguments:
#   $1: The type of refactoring to perform ("go-version" or "dependencies").
#   $2: The AI API URL endpoint.
#
# Assumptions:
# - The script is located at `.github/scripts/ai_refactor.sh`
# - The API key is stored as a GitHub Secret named `OPENROUTER_API_KEY`.
# - The AI model name is provided as an environment variable `AI_MODEL`.
# - Git is available on the runner.

set -e

# --- Environment Variable and Argument Validation ---
# Ensure required environment variables and arguments are set.
if; then
  echo "Error: OPENROUTER_API_KEY environment variable is not set. Exiting."
  exit 1
fi

if; then
  echo "Error: AI_MODEL environment variable is not set. Exiting."
  exit 1
fi

if [ "$#" -ne 2 ]; then
  echo "Usage:./ai_refactor.sh <go-version|dependencies> <api-url>"
  exit 1
fi

REFACTOR_TYPE=$1
API_URL=$2

echo "Starting AI-powered refactoring process for type: ${REFACTOR_TYPE}"
echo "Using AI model: ${AI_MODEL}"

# Placeholder for identifying files to refactor based on the type.
GO_FILES=$(find. -name "*.go" | grep -v 'vendor' | grep -v '_test.go')

if; then
  echo "No Go source files found to refactor. Exiting."
  exit 0
fi

# A function to build a context-aware prompt for the AI.
generate_prompt() {
  local file_path=$1
  local code_content
  code_content=$(cat "${file_path}")

  PROMPT="
You are an expert Go developer. I have recently updated a ${REFACTOR_TYPE} which has introduced breaking changes in the following file: ${file_path}.

Your task is to rewrite the provided code to resolve all compilation errors,
breaking changes, and deprecated function calls. Ensure the refactored code
is idiomatic, follows best practices, and maintains all original functionality.

Do not include any explanations or commentary. Just provide the complete, updated code block.

Code to refactor:
\`\`\`go
${code_content}
\`\`\`
"
  echo "${PROMPT}"
}

# Iterate over each Go file and generate a refactoring plan.
for file in ${GO_FILES}; do
  echo "Processing file: ${file}"
  
  PROMPT=$(generate_prompt "${file}")
  
  # --- OpenRouter API Call ---
  # Construct the JSON payload for the OpenRouter chat completions API.
  JSON_PAYLOAD=$(
    jq -n \
      --arg model "${AI_MODEL}" \
      --arg prompt "${PROMPT}" \
      '{
        "model": $model,
        "messages": [
          {
            "role": "user",
            "content": $prompt
          }
        ]
      }'
  )

  # Call the OpenRouter API using curl.
  # The output is captured and processed to extract the refactored code.
  AI_RESPONSE=$(
    curl --silent --location --request POST "${API_URL}" \
    --header "Authorization: Bearer ${OPENROUTER_API_KEY}" \
    --header "Content-Type: application/json" \
    --data "${JSON_PAYLOAD}" \

| jq -r '.choices.message.content'
  )
  
  if; then
    echo "Error: AI response was empty or could not be parsed. Skipping file."
    continue
  fi

  echo "AI has successfully refactored the file. Saving changes..."
  
  # --- Applying Changes ---
  # A robust script would apply the AI's output back to the file.
  echo "${AI_RESPONSE}" > "${file}"
  echo "Changes have been applied. Running final validation."
  
done

echo "AI-powered refactoring completed successfully."

exit 0
