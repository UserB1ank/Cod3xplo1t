package scg

import (
	"crypto/sha256"
	"embed"
	"fmt"
)

//go:embed builder.go edges.go frontend.go id.go index.go model.go
var implementationSource embed.FS

// ImplementationDigest fingerprints the compiled engine sources for plugin provenance.
func ImplementationDigest() string {
	var data []byte
	for _, name := range []string{"builder.go", "edges.go", "frontend.go", "id.go", "index.go", "model.go"} {
		raw, _ := implementationSource.ReadFile(name)
		data = append(data, []byte(name+"\x00")...)
		data = append(data, raw...)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
