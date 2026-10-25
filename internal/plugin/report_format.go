package plugin

import (
	"encoding/json"
	"mime"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func validateReport(media string, raw []byte) error {
	media, _, err := mime.ParseMediaType(media)
	if err != nil || len(raw) == 0 || !utf8.Valid(raw) {
		return ErrInvalid
	}
	switch media {
	case "text/markdown", "text/plain":
		return nil
	case "application/json", "application/sarif+json":
		if _, err := jsoncanonicalizer.Transform(raw); err != nil {
			return ErrInvalid
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return ErrInvalid
		}
		if media == "application/sarif+json" {
			var v string
			var runs []json.RawMessage
			if json.Unmarshal(obj["version"], &v) != nil || v != "2.1.0" || json.Unmarshal(obj["runs"], &runs) != nil || runs == nil {
				return ErrInvalid
			}
		}
		return nil
	default:
		return ErrUnsupported
	}
}
