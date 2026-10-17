package publication

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ErrInvalidView reports a malformed revision view id.
var ErrInvalidView = errors.New("publication: invalid view id")

// View is the stable reader address of one revision: it carries the scope and
// the revision id, so a client can read a published version without asking for
// "latest" and without server-side session state.
type View struct {
	ID       string `json:"view_id"`
	Revision string `json:"revision"`
	Scope    Scope  `json:"scope"`
}

type viewDescriptor struct {
	Project  string `json:"p"`
	Snapshot string `json:"s"`
	Revision string `json:"r"`
}

// NewView encodes the scope and revision into a self-describing view id.
func NewView(scope Scope, revision string) (View, error) {
	if scope.ProjectID == "" || scope.SnapshotID == "" || revision == "" || revision == "rev-0" {
		return View{}, ErrInvalidView
	}
	raw, err := json.Marshal(viewDescriptor{scope.ProjectID, scope.SnapshotID, revision})
	if err != nil {
		return View{}, err
	}
	return View{ID: "view-" + base64.RawURLEncoding.EncodeToString(raw), Revision: revision, Scope: scope}, nil
}

// ParseView decodes a revision view id back to its scope and revision.
func ParseView(viewID string) (Scope, string, error) {
	if !strings.HasPrefix(viewID, "view-") {
		return Scope{}, "", ErrInvalidView
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(viewID, "view-"))
	if err != nil {
		return Scope{}, "", ErrInvalidView
	}
	var descriptor viewDescriptor
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		return Scope{}, "", ErrInvalidView
	}
	if descriptor.Project == "" || descriptor.Snapshot == "" || descriptor.Revision == "" {
		return Scope{}, "", ErrInvalidView
	}
	return Scope{ProjectID: descriptor.Project, SnapshotID: descriptor.Snapshot}, descriptor.Revision, nil
}
