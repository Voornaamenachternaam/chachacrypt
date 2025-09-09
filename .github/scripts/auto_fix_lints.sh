#!/usr/bin/env bash
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  sudo apt-get update && sudo apt-get install -y jq
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -sL -o "$TMPDIR/golangci.tgz" "https://github.com/golangci/golangci-lint/releases/download/v2.4.0/golangci-lint-2.4.0-linux-amd64.tar.gz"
  tar -xzf "$TMPDIR/golangci.tgz" -C "$TMPDIR"
  GOLANGCI_BIN="$TMPDIR/golangci-lint"
else
  GOLANGCI_BIN="$(command -v golangci-lint)"
fi

"$GOLANGCI_BIN" run --out-format json ./... > "$TMPDIR/gc_output.json" || true

ERR_FILES=$(jq -r '.Issues[] | select(.FromLinter=="errcheck") | .Pos.Filename' "$TMPDIR/gc_output.json" 2>/dev/null | sort -u || true)

if [ -n "$ERR_FILES" ]; then
  for f in $ERR_FILES; do
    [ -f "$f" ] || continue
    PACKAGE=$(awk '/^package /{print $2; exit}' "$f")
    perl -0777 -pe 's/defer\s+([A-Za-z0-9_]+)\.Close\(\)/defer safeClose(\1)/g' -i "$f"
    DIR=$(dirname "$f")
    HELPER_FILE="$DIR/zz_safe_close.go"
    if ! grep -q 'func safeClose(' "$HELPER_FILE" 2>/dev/null; then
      cat > "$HELPER_FILE" <<EOF
package $PACKAGE

import (
	"fmt"
	"os"
)

func safeClose(f *os.File) {
	if f == nil {
		return
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to close file: %v\n", err)
	}
}
EOF
      git add "$HELPER_FILE"
    fi
  done
fi

find . -name '*.go' -not -path "./vendor/*" -print0 | xargs -0 goimports -w || true

if [ -n "$(git status --porcelain)" ]; then
  git add -A
  git commit -m "chore(ci): deterministic errcheck safeClose fixes" || true
fi
