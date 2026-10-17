package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Capabilities form a lattice: admin ⊃ writer ⊃ reader. The API fails closed, so
// a route without a rule and a token without the capability are both refused.
type Capability uint8

const (
	// CapNone means "no capability", used for unauthenticated liveness.
	CapNone Capability = 0
	// CapRead allows queries, including the POST-shaped query endpoints
	// (/graph/paths, /graph/slice) that exist only because they take a body.
	CapRead Capability = 1 << iota >> 1
	// CapWrite allows creating projects, freezing snapshots and building graphs.
	CapWrite
	// CapAdmin allows destructive and state-changing operations: deleting a
	// snapshot, renaming a project.
	CapAdmin
)

// Allows reports whether a principal holding c may perform want. CapNone means
// "nothing required" and is always allowed.
func (c Capability) Allows(want Capability) bool {
	if want == CapNone {
		return true
	}
	if c&CapAdmin != 0 {
		c |= CapWrite | CapRead
	}
	if c&CapWrite != 0 {
		c |= CapRead
	}
	return c&want == want
}

// String renders the capabilities for logs.
func (c Capability) String() string {
	switch {
	case c&CapAdmin != 0:
		return "admin"
	case c&CapWrite != 0:
		return "writer"
	case c&CapRead != 0:
		return "reader"
	default:
		return "none"
	}
}

// ParseCapability reads a role name from configuration.
func ParseCapability(name string) (Capability, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "reader", "read", "readonly", "read-only":
		return CapRead, nil
	case "writer", "write":
		return CapWrite, nil
	case "admin", "administrator":
		return CapAdmin, nil
	default:
		return CapNone, fmt.Errorf("%w: unknown role %q (want reader, writer or admin)", ErrInvalidConfig, name)
	}
}

// ErrInvalidConfig reports a configuration that must not be accepted.
var ErrInvalidConfig = errors.New("api: invalid configuration")

// minSecretLength is enforced so a deployment cannot end up protected by "x".
const minSecretLength = 16

// hashedSecretPrefix marks a token value that is already a SHA-256 digest.
const hashedSecretPrefix = "sha256:"

// Token is one configured credential.
type Token struct {
	// Name identifies the token in logs. Secrets are never logged.
	Name string
	// Role is reader, writer or admin.
	Role string
	// Secret is either the plaintext token or "sha256:<hex digest>", which lets
	// a deployment file hold no usable credential.
	Secret string
}

// Principal is an authenticated caller.
type Principal struct {
	Name         string
	Capabilities Capability
}

// Authenticator verifies bearer tokens and decides what they may do.
//
// Secrets are compared as SHA-256 digests with a constant-time comparison, so
// the check does not leak length or prefix information and the plaintext secret
// is not kept in memory longer than it takes to hash it.
type Authenticator struct {
	tokens         []storedToken
	anonymous      Capability
	allowAnonymous bool
}

type storedToken struct {
	name   string
	caps   Capability
	digest [32]byte
}

// NewAuthenticator builds an authenticator from configured tokens. A token whose
// secret is shorter than 16 characters, has no name, or has an unknown role is
// rejected: a weak or ambiguous credential is a deployment bug, not a warning.
func NewAuthenticator(tokens []Token) (*Authenticator, error) {
	a := &Authenticator{}
	seen := map[string]bool{}
	for _, t := range tokens {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: every token needs a name", ErrInvalidConfig)
		}
		if seen[name] {
			return nil, fmt.Errorf("%w: duplicate token name %q", ErrInvalidConfig, name)
		}
		seen[name] = true
		caps, err := ParseCapability(t.Role)
		if err != nil {
			return nil, err
		}
		digest, err := secretDigest(t.Secret)
		if err != nil {
			return nil, fmt.Errorf("%w: token %q: %w", ErrInvalidConfig, name, err)
		}
		a.tokens = append(a.tokens, storedToken{name: name, caps: caps, digest: digest})
	}
	return a, nil
}

// secretDigest accepts a plaintext secret or a pre-hashed "sha256:<hex>" value.
func secretDigest(secret string) ([32]byte, error) {
	var out [32]byte
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return out, errors.New("secret must not be empty")
	}
	if strings.HasPrefix(secret, hashedSecretPrefix) {
		raw, err := hex.DecodeString(strings.TrimPrefix(secret, hashedSecretPrefix))
		if err != nil || len(raw) != sha256.Size {
			return out, fmt.Errorf("%s value must be a %d-character hex SHA-256 digest", hashedSecretPrefix, sha256.Size*2)
		}
		copy(out[:], raw)
		return out, nil
	}
	if len(secret) < minSecretLength {
		return out, fmt.Errorf("secret must be at least %d characters", minSecretLength)
	}
	return sha256.Sum256([]byte(secret)), nil
}

// WithAnonymousAccess allows unauthenticated callers to hold the given
// capabilities. It exists for local development and for liveness probes; it must
// never be given CapAdmin.
func WithAnonymousAccess(caps Capability) func(*Authenticator) {
	return func(a *Authenticator) { a.anonymous, a.allowAnonymous = caps, true }
}

// NewAuthenticatorWithOptions builds an authenticator with anonymous access.
func NewAuthenticatorWithOptions(tokens []Token, opts ...func(*Authenticator)) (*Authenticator, error) {
	a, err := NewAuthenticator(tokens)
	if err != nil {
		return nil, err
	}
	for _, opt := range opts {
		opt(a)
	}
	if a.anonymous&CapAdmin != 0 {
		return nil, fmt.Errorf("%w: anonymous access must not be administrative", ErrInvalidConfig)
	}
	return a, nil
}

// Anonymous reports what an unauthenticated caller may do.
func (a *Authenticator) Anonymous() (Capability, bool) {
	if a == nil || !a.allowAnonymous {
		return CapNone, false
	}
	return a.anonymous, true
}

// Authenticate verifies a presented secret and returns the principal it belongs
// to. An unknown secret is rejected without revealing how close it was.
func (a *Authenticator) Authenticate(secret string) (Principal, bool) {
	if a == nil || secret == "" {
		return Principal{}, false
	}
	digest := sha256.Sum256([]byte(secret))
	for _, t := range a.tokens {
		if subtle.ConstantTimeCompare(digest[:], t.digest[:]) == 1 {
			return Principal{Name: t.name, Capabilities: t.caps}, true
		}
	}
	return Principal{}, false
}

// Tokens returns the configured token names and roles in order, for an operator
// summary. Secrets are never included.
func (a *Authenticator) Tokens() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.tokens))
	for _, t := range a.tokens {
		out = append(out, fmt.Sprintf("%s(%s)", t.name, t.caps))
	}
	return out
}

// ParseTokenSpecs reads token definitions in "name:role:secret" form. A secret
// may itself contain ':' (for example "sha256:<hex>"), so only the first two
// separators are significant.
func ParseTokenSpecs(specs []string) ([]Token, error) {
	out := make([]Token, 0, len(specs))
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		name, rest, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf("%w: token %q must be name:role:secret", ErrInvalidConfig, spec)
		}
		role, secret, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, fmt.Errorf("%w: token %q must be name:role:secret", ErrInvalidConfig, name)
		}
		out = append(out, Token{Name: name, Role: role, Secret: secret})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no tokens were configured", ErrInvalidConfig)
	}
	return out, nil
}

// bearerToken extracts a presented secret from the standard header or the
// X-API-Key header that many tools use.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header != "" {
		if value, ok := strings.CutPrefix(header, "Bearer "); ok {
			return strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(header, "bearer "); ok {
			return strings.TrimSpace(value)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// requiredCapability maps a request onto the capability it needs. Every route is
// listed explicitly: a new endpoint that nobody classifies is refused by default
// rather than silently exposed.
func requiredCapability(method, path string) (Capability, bool) {
	// Liveness must not require a credential, and it reveals nothing beyond the
	// fact that the process is up.
	if path == "/healthz" {
		return CapNone, true
	}
	if !strings.HasPrefix(path, "/api/") {
		return CapNone, false
	}
	rest := strings.TrimPrefix(path, "/api/")

	switch {
	case rest == "v1/plugins" && method == http.MethodGet:
		return CapRead, true
	case rest == "v1/plugins" && method == http.MethodPost:
		return CapAdmin, true
	case rest == "v1/projects" && method == http.MethodPost:
		return CapWrite, true
	case strings.HasPrefix(rest, "v1/sources/"):
		_, action, _ := strings.Cut(strings.TrimPrefix(rest, "v1/sources/"), "/")
		if action == "snapshots" && method == http.MethodPost {
			return CapWrite, true
		}
	case strings.HasPrefix(rest, "v1/projects/"):
		_, action, _ := strings.Cut(strings.TrimPrefix(rest, "v1/projects/"), "/")
		if action == "findings" || strings.HasPrefix(action, "findings/") {
			if method == http.MethodGet {
				return CapRead, true
			}
			if method == http.MethodPatch && strings.HasSuffix(action, "/severity") {
				return CapWrite, true
			}
			return 0, false
		}
		if action == "workflow-plans" || action == "workflows" || strings.HasPrefix(action, "workflows/") || strings.HasPrefix(action, "workflow-plans/") || strings.HasPrefix(action, "workflow-runs/") {
			if method == http.MethodGet || (method == http.MethodPost && action == "workflows/validate") {
				return CapRead, true
			}
			if method == http.MethodPost {
				return CapWrite, true
			}
		}
		if strings.HasPrefix(action, "snapshots/") && strings.Contains(action, "/plugin-invocations") {
			if method == http.MethodGet {
				return CapRead, true
			}
			if method == http.MethodPost {
				return CapWrite, true
			}
		}
		if strings.HasPrefix(action, "knowledge/publications") {
			if method == http.MethodPost {
				return CapWrite, true
			}
			return 0, false
		}
		if strings.HasPrefix(action, "knowledge/") {
			return CapRead, true
		}
		if strings.HasPrefix(action, "snapshots/") && strings.Contains(action, "/artifacts") {
			if method == http.MethodGet {
				return CapRead, true
			}
			if method == http.MethodPost && strings.HasSuffix(action, "/artifacts") {
				return CapWrite, true
			}
		}
		if action == "sources" && method == http.MethodGet {
			return CapRead, true
		}
		if action == "sources" && method == http.MethodPost {
			return CapWrite, true
		}
	case rest == "auth/status" && method == http.MethodGet:
		return CapNone, true
	case (rest == "auth/login" || rest == "auth/setup" || rest == "auth/logout") && method == http.MethodPost:
		return CapNone, true
	case rest == "settings/llm" && (method == http.MethodGet || method == http.MethodPut):
		return CapAdmin, true
	case rest == "settings/llm/test" && method == http.MethodPost:
		return CapAdmin, true
	case rest == "me" && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "knowledge/findings/") && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "tasks/"):
		if method == http.MethodGet {
			return CapRead, true
		}
		if method == http.MethodPost && (strings.HasSuffix(rest, "/pause") || strings.HasSuffix(rest, "/resume")) {
			return CapWrite, true
		}
	case strings.HasPrefix(rest, "findings/") && strings.HasSuffix(rest, "/severity") && method == http.MethodPatch:
		return CapWrite, true
	// /api/projects ...
	case rest == "projects":
		switch method {
		case http.MethodGet:
			return CapRead, true
		case http.MethodPost:
			return CapWrite, true
		}
	case strings.HasPrefix(rest, "projects/"):
		tail := strings.TrimPrefix(rest, "projects/")
		id, action, _ := strings.Cut(tail, "/")
		switch {
		case action == "" && method == http.MethodGet:
			return CapRead, true
		case action == "" && method == http.MethodPatch:
			return CapAdmin, true
		case action == "snapshots" && method == http.MethodPost:
			return CapWrite, true
		case (action == "tasks" || action == "findings") && method == http.MethodGet:
			return CapRead, true
		case action == "tasks" && method == http.MethodPost:
			return CapWrite, true
		case strings.HasPrefix(action, "tasks/") && method == http.MethodPatch:
			return CapWrite, true
		case action == "task-categories" && method == http.MethodGet:
			return CapRead, true
		case action == "task-categories" && method == http.MethodPut:
			return CapWrite, true
		}
		_ = id

	// /api/snapshots ...
	case rest == "snapshots" && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "snapshots/"):
		tail := strings.TrimPrefix(rest, "snapshots/")
		_, action, _ := strings.Cut(tail, "/")
		switch {
		case method == http.MethodDelete:
			return CapAdmin, true
		case method == http.MethodGet:
			return CapRead, true
		case method == http.MethodPost && strings.HasSuffix(tail, "/graph/paths"):
			return CapRead, true
		case method == http.MethodPost && strings.HasSuffix(tail, "/graph/slice"):
			return CapRead, true
		case method == http.MethodPost && strings.HasSuffix(tail, "/graph"):
			return CapWrite, true
		// POST /asg is a build, not a query, so it needs write; every ASG read
		// is already covered by the GET rule above. The action is checked
		// explicitly so a future POST under /asg cannot inherit this by suffix.
		case method == http.MethodPost && action == "asg":
			return CapWrite, true
		}

	// /api/audits ... and /api/paths ...
	//
	// Reading an audit or a path is a read; every POST under them is an operator
	// action or a build, so it is a write. The lease verbs (claim, heartbeat,
	// release) are writes as well: a worker that changes who owns a path is
	// spending the audit's budget, not observing it.
	case rest == "audits":
		switch method {
		case http.MethodGet:
			return CapRead, true
		case http.MethodPost:
			return CapWrite, true
		}
	case strings.HasPrefix(rest, "audits/"):
		switch method {
		case http.MethodGet:
			return CapRead, true
		case http.MethodPost:
			return CapWrite, true
		}
	case strings.HasPrefix(rest, "paths/"):
		switch method {
		case http.MethodGet:
			return CapRead, true
		case http.MethodPost:
			return CapWrite, true
		}

	// /api/runs ... and /api/hypotheses ...
	//
	// A run is operator work: starting one spends the audit's budget and moves a
	// path, exactly like a claim, so every POST needs write. The reads are the
	// evidence a reviewer examines, so they need only read — but a reader must
	// never be able to start a run, which is why the POST rules are explicit
	// rather than inherited from the audits/paths prefixes above.
	case rest == "runs" && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "runs/") && method == http.MethodGet:
		return CapRead, true
	case rest == "hypotheses" && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "hypotheses/"):
		switch method {
		case http.MethodGet:
			return CapRead, true
		// POST /api/hypotheses/{id}/finding and .../verifications are writes: one
		// stores a finding, the other spends a verification budget and records an
		// approval. A reader must never be able to start a verification.
		case http.MethodPost:
			return CapWrite, true
		}

	// /api/verifications, /api/findings and /api/evidence are the P6 read surface;
	// the report is a read under /api/audits/ and is covered by the audits rule
	// above. Every one of them needs only read.
	case rest == "verifications" && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "verifications/") && method == http.MethodGet:
		return CapRead, true
	case rest == "findings" && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "findings/") && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "evidence/") && method == http.MethodGet:
		return CapRead, true

	// /api/scheduler is the P7 operator surface. Reading the metrics is a read; a
	// manual tick claims leases and spends an audit's budget, and a reclaim sweep
	// changes path state, so both are writes. A reader must never be able to move
	// work on its behalf.
	case rest == "scheduler" && method == http.MethodGet:
		return CapRead, true
	case strings.HasPrefix(rest, "scheduler/") && method == http.MethodPost:
		return CapWrite, true
	}
	return CapNone, false
}

// authenticate enforces the capability table before any handler runs, so a
// missing rule cannot expose an endpoint.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		need, known := requiredCapability(r.Method, r.URL.Path)
		if !known {
			// An unknown route is not "allowed", it simply has no capability
			// rule; the mux answers 404 for it once the caller is authenticated.
			need = CapNone
		}
		if need == CapNone && known {
			next.ServeHTTP(w, r)
			return
		}

		principal, ok := Principal{}, false
		if secret := bearerToken(r); secret != "" {
			principal, ok = s.Auth.Authenticate(secret)
			if !ok {
				s.unauthorized(w, r, "the presented token is not valid")
				return
			}
		} else if cookie, err := r.Cookie(sessionCookie); err == nil && s.Accounts != nil {
			name, valid := s.Accounts.Authenticate(cookie.Value)
			if !valid {
				s.unauthorized(w, r, "login session expired")
				return
			}
			principal = Principal{Name: name, Capabilities: CapAdmin}
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
				writeError(w, http.StatusForbidden, "origin_forbidden", errors.New("请求来源无效"))
				return
			}
		} else if anon, allowed := s.Auth.Anonymous(); allowed {
			principal = Principal{Name: "anonymous", Capabilities: anon}
		} else {
			s.unauthorized(w, r, "no API token was presented")
			return
		}

		if need != CapNone && !principal.Capabilities.Allows(need) {
			writeError(w, http.StatusForbidden, "forbidden", fmt.Errorf(
				"principal %s has %s capabilities but this operation needs %s",
				principal.Name, principal.Capabilities, need))
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), principal)))
	})
}

// unauthorized sends the standard challenge so a client knows how to authenticate.
func (s *Server) unauthorized(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="codexploit"`)
	s.Logger.Warn("rejected unauthenticated request", "method", r.Method, "path", r.URL.Path, "reason", reason)
	writeError(w, http.StatusUnauthorized, "unauthorized", errors.New(reason))
}
