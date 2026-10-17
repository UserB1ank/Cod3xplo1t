package graph

import (
	"crypto/sha256"
	"embed"
	"fmt"
)

//go:embed agentcoordinator.go agentfacts.go agenttools.go asg_query.go asgreader.go pathreader.go service.go slice.go traverse.go verifyplanner.go
var implementationSource embed.FS

// ImplementationDigest fingerprints the compiled engine sources for plugin provenance.
func ImplementationDigest() string {
	var data []byte
	for _, name := range []string{"agentcoordinator.go", "agentfacts.go", "agenttools.go", "asg_query.go", "asgreader.go", "pathreader.go", "service.go", "slice.go", "traverse.go", "verifyplanner.go"} {
		raw, _ := implementationSource.ReadFile(name)
		data = append(data, []byte(name+"\x00")...)
		data = append(data, raw...)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
