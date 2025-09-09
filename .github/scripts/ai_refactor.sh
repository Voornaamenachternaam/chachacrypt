#!/usr/bin/env bash
echo "Processing file: ${file}"
payload=$(build_prompt "$file" "$REFACTOR_TYPE")


# call the API
ai_output=$(call_openrouter "$payload") || {
echo "AI call failed for ${file}. Skipping file."
continue
}


# Try to parse output as JSON. We expect either an object {path,content} or array of such objects.
# Extract 'content' field safely using jq; if parsing fails, skip.
if echo "$ai_output" | jq -e . >/dev/null 2>&1; then
# Attempt to extract first element or object
entries=$(echo "$ai_output" | jq -c '. as $in | (if type=="array" then .[] else . end) | {path: .path, content: .content}') || true
if [ -z "${entries}" ]; then
echo "AI output didn't contain expected JSON with path/content keys for ${file}. Skipping."
continue
fi


# Loop entries and write files
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
# Only commit if something staged
if [ -n "$(git status --porcelain)" ]; then
git commit -m "chore(ai): apply AI-assisted refactors for ${REFACTOR_TYPE}"
else
echo "No changes to commit."
fi
else
echo "No modifications detected by AI run."
fi
 

exit 0
