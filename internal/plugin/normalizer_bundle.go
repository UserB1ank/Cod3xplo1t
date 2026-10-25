package plugin

import (
	"embed"
	"runtime"
	"sync"

	v2 "github.com/open-mcp-ai/Codexploit/contracts/v2"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

//go:embed canonical_v2.go payload.go references_v2.go enhancement_v2.go execution_v2.go report_format.go normalizer_bundle.go
var stageNormalizerSource embed.FS

// Fingerprint the actual transform, reference checks, canonical identity rules,
// payload schema and toolchain. A version label alone is not an integrity hash.
var stageNormalizerDigest = sync.OnceValue(func() string {
	data := []byte(stageNormalizer + "\x00" + runtime.Version() + "\x00" + scg.ImplementationDigest())
	files, _ := stageNormalizerSource.ReadDir(".")
	for _, file := range files {
		raw, _ := stageNormalizerSource.ReadFile(file.Name())
		data = append(data, []byte(file.Name()+"\x00")...)
		data = append(data, raw...)
	}
	for _, name := range []string{"stage-payload.schema.json", "stages.json"} {
		raw, _ := v2.Files.ReadFile(name)
		data = append(data, []byte(name+"\x00")...)
		data = append(data, raw...)
	}
	return digest(data)
})
