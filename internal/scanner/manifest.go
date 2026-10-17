package scanner

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
)

//go:embed manifest.json
var manifestSource embed.FS

// Manifest returns the canonical package manifest. The package installer reads
// the same bytes from manifest.json; the handshake compares the digest so a
// renamed or edited package cannot impersonate this tool.
func Manifest() []byte {
	raw, _ := manifestSource.ReadFile("manifest.json")
	return append([]byte(nil), raw...)
}

// ManifestDigest is the canonical manifest digest used by the process handshake.
func ManifestDigest() string {
	var value any
	_ = json.Unmarshal(Manifest(), &value)
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
