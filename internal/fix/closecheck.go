// internal/fix/closecheck.go
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./internal/fix/closecheck.go <paths>")
		os.Exit(1)
	}

	for _, root := range os.Args[1:] {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			updated := fixDeferClose(string(content))
			if updated != string(content) {
				formatted, ferr := format.Source([]byte(updated))
				if ferr == nil {
					os.WriteFile(path, formatted, 0644)
				}
			}
			return nil
		})
	}
}

func fixDeferClose(src string) string {
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "defer ") && strings.HasSuffix(trim, ".Close()") {
			obj := strings.TrimPrefix(trim, "defer ")
			obj = strings.TrimSuffix(obj, ".Close()")
			lines[i] = fmt.Sprintf("defer func() { if err := %s.Close(); err != nil { fmt.Println(\"close error:\", err) } }()", obj)
		}
	}
	return strings.Join(lines, "\n")
}
