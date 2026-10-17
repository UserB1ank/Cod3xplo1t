package plugin

import "encoding/json"

const BuiltinID = "builtin.go-parser"
const BuiltinVersion = "1.1.0"

func BuiltinManifest() json.RawMessage {
	return json.RawMessage(`{"api_version":"codexploit/v1","id":"builtin.go-parser","version":"1.1.0","name":"Go syntax parser","description":"Read-only Go AST and syntax facts; no build or dependency execution.","kind":"parser","languages":["Go"],"runtime":{"kind":"builtin"},"consumes":["source.snapshot"],"produces":["code.ast","code.facts"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object","properties":{"include_comments":{"type":"boolean"}},"additionalProperties":false}}`)
}
func BuiltinManifestDigest() string {
	var value any
	_ = json.Unmarshal(BuiltinManifest(), &value)
	raw, _ := json.Marshal(value)
	return digest(raw)
}
