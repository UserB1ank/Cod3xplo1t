// Package artifact defines immutable, scoped content references and storage ports.
package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
)

var (
	ErrNotFound  = errors.New("artifact: published reference not found in scope")
	ErrConflict  = errors.New("artifact: immutable reference conflicts")
	ErrIntegrity = errors.New("artifact: content digest or size mismatch")
	ErrBudget    = errors.New("artifact: byte budget exceeded")
	ErrInvalid   = errors.New("artifact: invalid reference or budget")
)

type Scope struct {
	ProjectID  string `json:"project_id"`
	SourceID   string `json:"source_id"`
	SnapshotID string `json:"snapshot_id"`
}

type Producer struct {
	PluginID      string `json:"plugin_id"`
	PluginVersion string `json:"plugin_version"`
	InvocationID  string `json:"invocation_id"`
	TaskID        string `json:"task_id,omitempty"`
	ConfigDigest  string `json:"config_digest"`
}

type Ref struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Scope     Scope    `json:"scope"`
	SHA256    string   `json:"sha256"`
	Bytes     int64    `json:"bytes"`
	MediaType string   `json:"media_type"`
	SchemaID  string   `json:"schema_id"`
	Producer  Producer `json:"producer"`
}

// Index publishes only after content verification. Implementations must fence
// snapshot deletion, check scope ownership and compare the entire immutable ref.
type Index interface {
	PublishArtifact(context.Context, Ref) error
	LookupArtifact(context.Context, Scope, string) (Ref, error)
	ListArtifacts(context.Context, Scope, string, int) ([]Ref, error)
	ArtifactScope(context.Context, string, string) (Scope, error)
}

type Store interface {
	Put(context.Context, Ref, io.Reader, int64) (Ref, error)
	Open(context.Context, Scope, string, int64) (io.ReadCloser, Ref, error)
	Stat(context.Context, Scope, string, int64) (Ref, error)
	List(context.Context, Scope, string, int) ([]Ref, error)
}

var refSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("common.schema.json")
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	document["$ref"] = "#/$defs/ArtifactRef"
	raw, err = json.Marshal(document)
	if err != nil {
		return nil, err
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(nil)
})

func (r Ref) Validate() error {
	if len(r.MediaType) > 200 || strings.ContainsAny(r.MediaType, "\r\n\x00") {
		return ErrInvalid
	}
	if _, _, err := mime.ParseMediaType(r.MediaType); err != nil {
		return ErrInvalid
	}
	schema, err := refSchema()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if err := schema.Validate(value); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	return nil
}
