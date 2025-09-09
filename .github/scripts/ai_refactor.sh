#!/usr/bin/env bash
set -euo pipefail

TYPE="${1:-}"
API_URL="${2:-}"

if [ -z "$TYPE" ] || [ -z "$API_URL" ]; then
  echo "Usage: $0 <patch|dependencies|go-version> <api-url>" >&2
  exit 1
fi

if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY not set" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y jq
  else
    echo "jq required but not available; aborting." >&2
    exit 1
  fi
fi

REPAIR_DIFF=$( [ -f repair.diff ] && sed -n '1,2000p' repair.diff | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g' || echo "" )

SYSTEM_PROMPT="You are an expert Go developer. Produce a unified patch (git diff/patch format) that fixes the repository issues. Output only the patch starting with 'diff --git'. If no changes are required, reply with 'NO_CHANGE'."

PAYLOAD=$(jq -n --arg model "${AI_MODEL:-qwen/qwen3-coder:free}" --arg system "$SYSTEM_PROMPT" --arg repair "$REPAIR_DIFF" '{
  model: $model,
  messages: [
    {role: "system", content: $system},
    {role: "user", content: ("Repair diff (may be empty):\n" + $repair + "\n\nInstruction: Return a unified patch (diff --git ...).")}
  ]
}')

RESPONSE_FILE=response_ai.json
MAX=3
i=0
while [ $i -lt $MAX ]; do
  i=$((i+1))
  HTTP=$(curl -sS -w '%{http_code}' -o "$RESPONSE_FILE" -X POST "$API_URL" -H "Content-Type: application/json" -H "Authorization: Bearer ${OPENROUTER_API_KEY}" -d "$PAYLOAD" || true)
  if [ "$HTTP" = "200" ] || [ "$HTTP" = "201" ]; then
    break
  fi
  if [ $i -lt $MAX ]; then
    sleep $((i*2))
  else
    echo "AI service failed HTTP $HTTP"
    cat "$RESPONSE_FILE" || true
    exit 1
  fi
done

if jq -e '.choices[0].message.content' "$RESPONSE_FILE" >/dev/null 2>&1; then
  jq -r '.choices[0].message.content' "$RESPONSE_FILE" > ai-response.txt
elif jq -e '.result[0].content[0].text' "$RESPONSE_FILE" >/dev/null 2>&1; then
  jq -r '.result[0].content[0].text' "$RESPONSE_FILE" > ai-response.txt
else
  cat "$RESPONSE_FILE"
  exit 1
fi

sed -n '/^diff --git /,$p' ai-response.txt > ai.patch || true

if [ -s ai.patch ]; then
  if git apply --check ai.patch; then
    git apply ai.patch
    git add -A
    git commit -m "chore(ai): apply AI patch" || true
  else
    echo "ai.patch failed git apply --check" >&2
    exit 1
  fi
else
  echo "NO_PATCH returned by AI or patch  empty"
fi
