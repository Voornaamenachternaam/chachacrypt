package main

import (
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var deferCloseRe = regexp.MustCompile(`(?m)^(?P<indent>\s*)defer\s+(?P<expr>.+?)\s*\.\s*Close\s*\(\s*\)\s*(?P<comment>//.*)?$`)

func main() {
	start := "."
	if len(os.Args) > 1 {
		start = os.Args[1]
	}
	filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Skip vendor and the internal fixer itself
			if d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Do not modify files under internal/fix (avoid modifying this tool)
		if strings.HasPrefix(filepath.Clean(path), filepath.Clean("internal/fix")) {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		src := string(data)
		newSrc := deferCloseRe.ReplaceAllStringFunc(src, func(m string) string {
			sub := deferCloseRe.FindStringSubmatch(m)
			if len(sub) < 3 {
				return m
			}
			indent := sub[1]
			expr := strings.TrimSpace(sub[2])
			comment := ""
			if len(sub) >= 4 {
				comment = sub[3]
			}
			// Build replacement preserving indentation and comment
			rep := fmt.Sprintf("%sdefer func() { if err := %s.Close(); err != nil { fmt.Fprintf(os.Stderr, \"warning: failed to close resource: %%v\\n\", err) } }() %s", indent, expr, comment)
			return rep
		})
		if newSrc != src {
			// try to format
			if formatted, ferr := format.Source([]byte(newSrc)); ferr == nil {
				_ = os.WriteFile(path, formatted, 0o644)
			} else {
				// fallback: write unformatted (should rarely happen)
				_ = os.WriteFile(path, []byte(newSrc), 0o644)
			}
		}
		return nil
	})
}
