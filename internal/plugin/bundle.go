package plugin

import (
	"embed"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"runtime"
)

//go:embed builtin.go parser.go host.go catalog.go bundle.go
var builtinSource embed.FS

// BuiltinPackageDigest binds the compiled adapter sources, frontend and Go
// toolchain. Changing the bundle requires a new plugin version for an upgrade.
func BuiltinPackageDigest() string {
	var data []byte
	for _, name := range []string{"builtin.go", "parser.go", "host.go", "catalog.go", "bundle.go"} {
		raw, _ := builtinSource.ReadFile(name)
		data = append(data, []byte(name+"\x00")...)
		data = append(data, raw...)
	}
	data = append(data, []byte(gofrontend.ImplementationDigest()+"\x00"+runtime.Version())...)
	return digest(data)
}
