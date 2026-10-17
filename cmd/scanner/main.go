// Command scanner runs the fixed-version process scanner plugin.
package main

import (
	"fmt"
	"os"

	"github.com/open-mcp-ai/Codexploit/internal/scanner"
)

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--manifest":
			_, _ = os.Stdout.Write(scanner.Manifest())
			return
		case "--version":
			fmt.Println(scanner.Version)
			return
		}
	}
	os.Exit(scanner.Main())
}
