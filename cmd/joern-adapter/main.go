// joern-adapter implements the sealed Joern parse-stage file-job boundary.
package main

import (
	"flag"
	"os"
)

func main() {
	requestPath := flag.String("request", "", "host job request")
	responsePath := flag.String("response", "", "host result")
	flag.Parse()
	if flag.NArg() != 0 {
		os.Exit(1)
	}
	if err := run(*requestPath, *responsePath); err != nil {
		os.Exit(1)
	}
}
