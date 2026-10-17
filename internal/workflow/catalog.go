// Package workflow owns immutable workflow definitions and compiled plans.
package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
)

var (
	ErrInvalid  = errors.New("workflow: invalid definition or compilation input")
	ErrConflict = errors.New("workflow: immutable version or head conflicts")
	ErrNotFound = errors.New("workflow: record not found in project")
)

type Node struct {
	ID             string          `json:"id"`
	PluginID       string          `json:"plugin_id"`
	PluginVersion  string          `json:"plugin_version"`
	Needs          []string        `json:"needs"`
	Config         json.RawMessage `json:"config"`
	TimeoutSeconds int             `json:"timeout_seconds"`
}
type Spec struct {
	APIVersion  string   `json:"api_version"`
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Inputs      []string `json:"inputs"`
	Nodes       []Node   `json:"nodes"`
}
type Record struct {
	ProjectID string    `json:"project_id"`
	Spec      Spec      `json:"spec"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"created_at"`
}
type Repository interface {
	ListWorkflows(context.Context, string, string, int) ([]Entry, error)
	SaveWorkflow(context.Context, Record, string) (Record, error)
	GetWorkflow(context.Context, string, string, string) (Record, error)
}
type Catalog struct{ Repository Repository }

func Digest(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

var specSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	raw, err := contracts.Files.ReadFile("workflow.schema.json")
	if err != nil {
		return nil, err
	}
	var s jsonschema.Schema
	if err = json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return s.Resolve(nil)
})

func Parse(raw json.RawMessage) (Spec, error) {
	var s Spec
	if len(raw) > 256<<10 {
		return s, ErrInvalid
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return s, ErrInvalid
	}
	schema, err := specSchema()
	if err != nil {
		return s, err
	}
	if schema.Validate(value) != nil {
		return s, ErrInvalid
	}
	canonical, _ := json.Marshal(value)
	err = json.Unmarshal(canonical, &s)
	return s, err
}
func (c *Catalog) Save(ctx context.Context, project string, raw json.RawMessage, expected string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	spec, err := Parse(raw)
	if err != nil {
		return Record{}, err
	}
	canonical, _ := json.Marshal(spec)
	return c.Repository.SaveWorkflow(ctx, Record{ProjectID: project, Spec: spec, Digest: Digest(canonical), CreatedAt: time.Now().UTC()}, expected)
}
func (c *Catalog) Get(ctx context.Context, project, id, version string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	return c.Repository.GetWorkflow(ctx, project, id, version)
}

// VersionAfter compares bounded decimal components without integer overflow.
func VersionAfter(candidate, current string) bool {
	if current == "" {
		return true
	}
	a, b := strings.Split(candidate, "."), strings.Split(current, ".")
	for i := 0; i < 3; i++ {
		x, y := strings.TrimLeft(a[i], "0"), strings.TrimLeft(b[i], "0")
		if len(x) != len(y) {
			return len(x) > len(y)
		}
		if x != y {
			return x > y
		}
	}
	return false
}

type Entry struct {
	Record
	HeadDigest string `json:"head_digest"`
}

func (c *Catalog) List(ctx context.Context, project, cursor string, limit int) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 || len(cursor) > 256 {
		return nil, ErrInvalid
	}
	return c.Repository.ListWorkflows(ctx, project, cursor, limit)
}
