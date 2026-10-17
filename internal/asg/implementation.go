package asg

import (
	"crypto/sha256"
	"embed"
	"fmt"
)

//go:embed build.go extract.go model.go rules.go
var implementationSource embed.FS

// ImplementationDigest fingerprints the compiled engine sources for plugin provenance.
func ImplementationDigest() string {
	var data []byte
	for _, name := range []string{"build.go", "extract.go", "model.go", "rules.go"} {
		raw, _ := implementationSource.ReadFile(name)
		data = append(data, []byte(name+"\x00")...)
		data = append(data, raw...)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
