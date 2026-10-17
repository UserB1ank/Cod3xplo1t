package path

import (
	"crypto/sha256"
	"embed"
	"fmt"
)

//go:embed backoff.go dedup.go generate.go model.go queue.go reader.go scope.go score.go service.go statemachine.go store.go task.go
var implementationSource embed.FS

// ImplementationDigest fingerprints the compiled engine sources for plugin provenance.
func ImplementationDigest() string {
	var data []byte
	for _, name := range []string{"backoff.go", "dedup.go", "generate.go", "model.go", "queue.go", "reader.go", "scope.go", "score.go", "service.go", "statemachine.go", "store.go", "task.go"} {
		raw, _ := implementationSource.ReadFile(name)
		data = append(data, []byte(name+"\x00")...)
		data = append(data, raw...)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
