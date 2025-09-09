package main

import (
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	start := "."
	if len(os.Args) > 1 {
		start = os.Args[1]
	}

	err := filepath.WalkDir(start, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			fmt.Fprintf(os.Stderr, "walk error for %s: %v\n", path, walkErr)
			return nil
		}
		// skip directories and non-go files
		if d.IsDir() {
			// skip vendor and this internal fixer directory
			if d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// do not modify files under internal/fix
		cleanPath := filepath.Clean(path)
		if strings.HasPrefix(cleanPath, filepath.Clean("internal/fix")) {
			return nil
		}

		data, rerr := os.ReadFile(path)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "read error for %s: %v\n", path, rerr)
			return nil
		}
		src := string(data)
		lines := strings.Split(src, "\n")
		changed := false

		for i, line := range lines {
			trim := strings.TrimSpace(line)
			if !strings.HasPrefix(trim, "defer ") || !strings.Contains(trim, ".Close()") {
				continue
			}

			// preserve inline comment if present
			comment := ""
			cidx := strings.Index(line, "//")
			lineNoComment := line
			if cidx >= 0 {
				comment = line[cidx:]
				lineNoComment = line[:cidx]
			}

			// find ".Close(" index in the non-comment portion
			closeIdx := strings.Index(lineNoComment, ".Close(")
			if closeIdx == -1 {
				continue
			}

			// find "defer" index to preserve indentation
			defIdx := strings.Index(lineNoComment, "defer")
			if defIdx == -1 {
				continue
			}

			indent := lineNoComment[:defIdx]
			exprPart := lineNoComment[defIdx+len("defer") : closeIdx]
			expr := strings.TrimSpace(exprPart)
			if expr == "" {
				continue
			}

			// build replacement: defer func() { if err := <expr>.Close(); err != nil { fmt.Fprintf(os.Stderr, "...", err) } }() <comment>
			rep := fmt.Sprintf("%sdefer func() { if err := %s.Close(); err != nil { fmt.Fprintf(os.Stderr, \"warning: failed to close resource: %%v\\n\", err) } }() %s", indent, expr, comment)
			lines[i] = rep
			changed = true
		}

		if changed {
			newSrc := strings.Join(lines, "\n")
			if formatted, ferr := format.Source([]byte(newSrc)); ferr == nil {
				if werr := os.WriteFile(path, formatted, 0644); werr != nil {
					fmt.Fprintf(os.Stderr, "write error for %s: %v\n", path, werr)
				}
			} else {
				if werr := os.WriteFile(path, []byte(newSrc), 0644); werr != nil {
					fmt.Fprintf(os.Stderr, "write error for %s: %v\n", path, werr)
				}
			}
		}

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "WalkDir failed: %v\n", err)
		os.Exit(1)
	}
}
