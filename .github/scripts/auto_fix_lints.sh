#!/usr/bin/env bash
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y jq
  else
    echo "jq required but not available; aborting." >&2
    exit 1
  fi
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git required but not available; aborting." >&2
  exit 1
fi

if ! command -v goimports >/dev/null 2>&1; then
  GO111MODULE=on go install golang.org/x/tools/cmd/goimports@latest
  echo "$(go env GOPATH)/bin" >> $GITHUB_PATH || true
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

if [ -z "$ERR_FILES" ]; then
  echo "No errcheck issues detected."
  exit 0
fi

for f in $ERR_FILES; do
  if [ ! -f "$f" ]; then
    continue
  fi
  perl -0777 -pe 's/defer\s+([A-Za-z0-9_]+)\.Close\(\)/defer closeFile($1)/g' -i "$f"
done

PKG_NAME=$(awk '/^package /{print $2; exit}' $(git ls-files '*.go' | head -n1) 2>/dev/null || echo "main")
HELPER_FILE="zz_close_helper.go"
if ! grep -q 'func closeFile(' "$HELPER_FILE" 2>/dev/null; then
  cat > "$HELPER_FILE" <<EOF
package ${PKG_NAME}

import (
	"fmt"
	"os"
)

func closeFile(f *os.File) {
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

if command -v goimports >/dev/null 2>&1; then
  find . -name '*.go' -not -path "./vendor/*" -print0 | xargs -0 -n1 goimports -w || true
fi

if [ -n "$(git status --porcelain)" ]; then
  git add -A
  git commit -m "chore(ci): automated errcheck close fixe s" || true
fi
