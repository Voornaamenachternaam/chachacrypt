#!/usr/bin/env bash
set -euo pipefail

# Ensure jq is available
if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y jq
  else
    echo "jq is required but not available." >&2
    exit 1
  fi
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Ensure golangci-lint binary
if ! command -v golangci-lint >/dev/null 2>&1; then
  curl -sL -o "$TMPDIR/golangci.tgz" "https://github.com/golangci/golangci-lint/releases/download/v2.4.0/golangci-lint-2.4.0-linux-amd64.tar.gz"
  tar -xzf "$TMPDIR/golangci.tgz" -C "$TMPDIR"
  GOLANGCI_BIN="$TMPDIR/golangci-lint"
else
  GOLANGCI_BIN="$(command -v golangci-lint)"
fi

# Run once to collect errcheck issues
"$GOLANGCI_BIN" run --out-format json ./... > "$TMPDIR/gc_output.json" || true

# Files with errcheck related to *.Close()
ERR_FILES=$(jq -r '
  .Issues[]?
  | select(.FromLinter=="errcheck")
  | select(.Text | test("Close\\("))
  | .Pos.Filename
' "$TMPDIR/gc_output.json" 2>/dev/null | sort -u || true)

if [ -z "$ERR_FILES" ]; then
  echo "No errcheck Close() issues detected."
else
  for f in $ERR_FILES; do
    [ -f "$f" ] || continue

    # Extract package name
    PKG=$(awk '/^package / {print $2; exit}' "$f")
    [ -n "$PKG" ] || PKG="main"

    # Robust replacements:
    # 1) defer <ident>.Close()
    # 2) defer (<expr>).Close()
    # 3) defer <ident> . Close ( )
    # Preserve line comments.
    perl -0777 -pe '
      s/\bdefer\s+([A-Za-z0-9_()*\s\.]+?)\s*\.\s*Close\s*\(\s*\)\s*(\/\/[^\n]*)?$/defer safeClose($1)$2/mg;
    ' -i "$f"

    # Helper per package directory (idempotent)
    DIR=$(dirname "$f")
    HELPER_FILE="$DIR/zz_safe_close.go"
    if ! grep -q 'func safeClose(' "$HELPER_FILE" 2>/dev/null; then
      cat > "$HELPER_FILE" <<EOF
package $PKG

import (
	"fmt"
	"io"
	"os"
)

func safeClose(c interface{}) {
	switch v := c.(type) {
	case *os.File:
		if v == nil {
			return
		}
		if err := v.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close file: %v\n", err)
		}
	case io.Closer:
		if v == nil {
			return
		}
		if err := v.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close resource: %v\n", err)
		}
	default:
		// Best effort: ignore if not closable
	}
}
EOF
      git add "$HELPER_FILE"
    fi
  done
fi

# Normalize imports
if ! command -v goimports >/dev/null 2>&1; then
  GO111MODULE=on go install golang.org/x/tools/cmd/goimports@latest
  echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH" || true
fi
find . -name '*.go' -not -path './vendor/*' -print0 | xargs -0 goimports -w || true

# Commit if changes exist
if [ -n "$(git status --porcelain)" ]; then
  git add -A
  git commit -m "chore(ci): deterministic errcheck Close() fixes via safeClose" || true
fi
