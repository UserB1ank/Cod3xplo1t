package asg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// This file is the rule set: what a route registration, an input, a sink and a
// security control look like to a name- and shape-based analysis of the SCG.
//
// The rules are data because they are the part of this package most likely to be
// wrong and most likely to be extended: a reviewer must be able to read them,
// and a new framework must be a new row, not new control flow.

// Entry kinds recorded in an EntryPoint node's detail.
const (
	EntryHTTPRoute       = "http_route"
	EntryRPCHandler      = "rpc_handler"
	EntryGraphQLHandler  = "graphql_handler"
	EntryMessageConsumer = "message_consumer"
	EntryCLICommand      = "cli_command"
)

// Trust boundary kinds.
const (
	BoundaryNetwork    = "network"
	BoundaryMessage    = "message"
	BoundaryProcess    = "process"
	BoundaryFilesystem = "filesystem"
)

// Source kinds recorded in an AttackerControlledInput node's subject.
const (
	SourceQueryParam = "query_param"
	SourcePathParam  = "path_param"
	SourceBody       = "body"
	SourceHeader     = "header"
	SourceCookie     = "cookie"
	SourceForm       = "form"
	SourceFile       = "file_content"
	SourceMessage    = "message_payload"
	SourceEnv        = "env"
	SourceCLIArg     = "cli_arg"
)

// Sink kinds recorded in a SensitiveOperation node's subject.
const (
	SinkSQL             = "sql_execution"
	SinkFileWrite       = "file_write"
	SinkProcess         = "process_execution"
	SinkNetwork         = "network_request"
	SinkDeserialization = "deserialization"
	SinkSensitiveOutput = "sensitive_output"
)

// Control kinds recorded in a SecurityControl node's subject.
const (
	ControlAuthentication    = "authentication"
	ControlAuthorization     = "authorization"
	ControlInputValidation   = "input_validation"
	ControlEncoding          = "encoding"
	ControlParameterization  = "parameterization"
	ControlPathNormalization = "path_normalization"
)

// Asset kinds recorded in an Asset node's subject.
const (
	AssetTable    = "database_table"
	AssetFile     = "file_path"
	AssetCommand  = "command"
	AssetEndpoint = "endpoint"
)

// FrameworkRule recognises the route and middleware registration style of one
// web framework or router.
type FrameworkRule struct {
	Name string
	// Constructors are receiver-provenance fragments: `r := gin.Default()` binds
	// r to "gin.Default", which is what attributes `r.GET(...)` to gin without
	// type checking.
	Constructors []string
	// RouteMethods register a route on a receiver (gin, echo, fiber, chi, ...).
	RouteMethods []string
	// RouteMethodPrefixes match families of registration methods, for example
	// gRPC's RegisterXxxServer.
	RouteMethodPrefixes []string
	// AllowPathless marks registrations that carry no route path (gRPC service
	// registration), so they are not rejected for lacking a path literal.
	AllowPathless bool
	// PackageRouteFuncs are package-level registration functions
	// (net/http's Handle and HandleFunc, httprouter's ...).
	PackageRouteFuncs []string
	// PackagePaths are import-path fragments used to attribute a call whose
	// qualified name carries the package.
	PackagePaths []string
	// MiddlewareMethods register middleware on the same receiver.
	MiddlewareMethods []string
	// HandlerArgIndex is where the handler sits in the argument list; -1 means the
	// handler is not passed to the registration call.
	HandlerArgIndex int
	// PathArgIndex is where the route path sits.
	PathArgIndex int
	// EntryKind is the entry point kind this rule produces.
	EntryKind string
	// Boundary is the trust boundary the entry crosses.
	Boundary string
	Note     string
}

// DefaultFrameworkRules returns the P3 rule table. Every rule is shape-based:
// receiver provenance, method name and a path-shaped string argument. It cannot
// see type information, so a rule that fires still records how it decided.
func DefaultFrameworkRules() []FrameworkRule {
	return []FrameworkRule{
		{
			Name:              "gin",
			Constructors:      []string{"gin.Default", "gin.New", "gin.engine"},
			RouteMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "Any", "Handle"},
			PackagePaths:      []string{"gin-gonic/gin"},
			MiddlewareMethods: []string{"Use"},
			PathArgIndex:      0, HandlerArgIndex: 1, EntryKind: EntryHTTPRoute, Boundary: BoundaryNetwork,
			Note: "gin route registration; the handler argument may be a middleware chain, in which case the last resolved symbol is used",
		},
		{
			Name:              "echo",
			Constructors:      []string{"echo.New"},
			RouteMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "Any", "Add", "File", "Static"},
			PackagePaths:      []string{"labstack/echo"},
			MiddlewareMethods: []string{"Use", "Pre"},
			PathArgIndex:      0, HandlerArgIndex: 1, EntryKind: EntryHTTPRoute, Boundary: BoundaryNetwork,
			Note: "echo route registration; middleware chains end with the handler",
		},
		{
			Name:              "fiber",
			Constructors:      []string{"fiber.New", "fiber.NewApp"},
			RouteMethods:      []string{"Get", "Post", "Put", "Patch", "Delete", "Head", "Options", "All", "Add"},
			PackagePaths:      []string{"gofiber/fiber"},
			MiddlewareMethods: []string{"Use"},
			PathArgIndex:      0, HandlerArgIndex: 1, EntryKind: EntryHTTPRoute, Boundary: BoundaryNetwork,
		},
		{
			Name:              "chi",
			Constructors:      []string{"chi.NewRouter", "chi.NewMux"},
			RouteMethods:      []string{"Get", "Post", "Put", "Patch", "Delete", "Head", "Options", "Handle", "HandleFunc", "Method"},
			PackagePaths:      []string{"go-chi/chi"},
			MiddlewareMethods: []string{"Use", "With"},
			PathArgIndex:      0, HandlerArgIndex: 1, EntryKind: EntryHTTPRoute, Boundary: BoundaryNetwork,
		},
		{
			Name:              "net/http",
			Constructors:      []string{"http.NewServeMux"},
			RouteMethods:      []string{"Handle", "HandleFunc"},
			PackageRouteFuncs: []string{"http.Handle", "http.HandleFunc", "net/http.Handle", "net/http.HandleFunc"},
			PackagePaths:      []string{"net/http"},
			PathArgIndex:      0, HandlerArgIndex: 1, EntryKind: EntryHTTPRoute, Boundary: BoundaryNetwork,
			Note: "net/http mux registration or the package-level default mux",
		},
		{
			Name:              "gorilla/mux",
			Constructors:      []string{"mux.NewRouter"},
			RouteMethods:      []string{"Handle", "HandleFunc", "Methods", "Path", "PathPrefix"},
			PackagePaths:      []string{"gorilla/mux"},
			MiddlewareMethods: []string{"Use"},
			PathArgIndex:      0, HandlerArgIndex: 1, EntryKind: EntryHTTPRoute, Boundary: BoundaryNetwork,
			Note: "gorilla/mux chains route builders; the path may be set by a chained Path() call",
		},
		{
			Name:         "httprouter",
			Constructors: []string{"httprouter.New"},
			RouteMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "Handle"},
			PackagePaths: []string{"julienschmidt/httprouter"},
			PathArgIndex: 0, HandlerArgIndex: 1, EntryKind: EntryHTTPRoute, Boundary: BoundaryNetwork,
		},
		{
			Name:         "grpc",
			PackagePaths: []string{"google.golang.org/grpc"},
			// RegisterXxxServer(s, impl) is the gRPC registration shape.
			RouteMethods:        []string{"RegisterService", "Serve"},
			RouteMethodPrefixes: []string{"Register"},
			AllowPathless:       true,
			PathArgIndex:        -1, HandlerArgIndex: 0, EntryKind: EntryRPCHandler, Boundary: BoundaryNetwork,
			Note: "gRPC service registration; the concrete handler is the service implementation passed as an argument, and where the service is served from is not resolved here",
		},
	}
}

// IsRouteRegistration reports whether a call site registers a route for this
// rule, and returns the arguments that made it look that way.
func (r FrameworkRule) matchRoute(calleeText, receiverFrom string) bool {
	if calleeText == "" {
		return false
	}
	for _, fn := range r.PackageRouteFuncs {
		if calleeText == fn || strings.HasSuffix(calleeText, "."+fn) {
			return true
		}
	}
	_, method, ok := strings.Cut(calleeText, ".")
	if !ok {
		return false
	}
	for _, m := range r.RouteMethods {
		if method == m {
			return true
		}
	}
	for _, prefix := range r.RouteMethodPrefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}

// attributes reports whether the receiver provenance or the qualified callee
// name points at this framework.
func (r FrameworkRule) attributes(receiverFrom, calleeQualified string) attribution {
	for _, c := range r.Constructors {
		if receiverFrom == c || strings.HasSuffix(receiverFrom, "."+c) || c == receiverFrom {
			return attribConstructor
		}
	}
	for _, p := range r.PackagePaths {
		if strings.Contains(calleeQualified, p) {
			return attribQualified
		}
		if strings.Contains(receiverFrom, p) {
			return attribConstructor
		}
	}
	return attribNone
}

type attribution string

const (
	attribNone        attribution = "none"
	attribConstructor attribution = "constructor"
	attribQualified   attribution = "qualified_package"
)

// RouteRegisteringMethods is used to reject a route-shaped call when the method
// is not a registration method of any rule.
func (r FrameworkRule) isMiddlewareMethod(method string) bool {
	for _, m := range r.MiddlewareMethods {
		if m == method {
			return true
		}
	}
	return false
}

// MatchRule is one callee-name pattern for a source, sink or control.
type MatchRule struct {
	// Kind is the source/sink/control kind this rule records.
	Kind string
	// Names are exact callee base names (the part after the last dot).
	Names []string
	// Suffixes are callee text suffixes, for example ".Exec" or "FlagSet.String".
	Suffixes []string
	// QualifiedContains matches the resolved qualified name, which is how an
	// external package is recognised when its name is unambiguous
	// ("database/sql.DB.Query").
	QualifiedContains []string
	// NameRegex is a small name predicate; it is not a regular expression to keep
	// the rules readable.
	NamePrefix                  string
	NameContainsCaseInsensitive []string
	// KindDetail is copied into the node detail for the reviewer.
	KindDetail string
	// Heuristic marks name-based rules whose result can be a false positive.
	Heuristic bool
	// Evidence is the evidence status the rule produces.
	Evidence EvidenceStatus
	// Note explains the rule's limits.
	Note string
}

// DefaultSourceRules returns the input rules.
//
// Each rule states the callee shape and, when the name alone is ambiguous, the
// package that must be visible as well.
func DefaultSourceRules() []MatchRule {
	return []MatchRule{
		{Kind: SourceQueryParam, Suffixes: []string{".Query", ".QueryParam", ".QueryParams", ".DefaultQuery", "Query().Get"},
			QualifiedContains: []string{"url.Values", ".URL", "Context.", "Ctx."}, Evidence: StatusObserved,
			Note: "query parameters and URL values; the receiver determines whether this is a request URL"},
		{Kind: SourcePathParam, Suffixes: []string{".Param", ".PathValue", ".URLParam", ".Params"}, Evidence: StatusObserved},
		{Kind: SourceBody, Suffixes: []string{".Bind", ".BindJSON", ".BindXML", ".ShouldBind", ".ShouldBindJSON", ".FormValue", ".PostFormValue", ".MultipartForm", ".FormFile", "NewDecoder", "ReadAll"},
			QualifiedContains: []string{"Context.", "Ctx.", "http.Request", "body", "Body", "io.", "json."}, Evidence: StatusObserved,
			Note: "body-shaped reads: request bodies, form values, multipart parts and decoders"},
		{Kind: SourceHeader, Suffixes: []string{".GetHeader", "Header.Get", ".HeaderValues"}, Evidence: StatusObserved},
		{Kind: SourceCookie, Suffixes: []string{".Cookie", ".Cookies"}, Evidence: StatusObserved},
		{Kind: SourceFile, Names: []string{"ReadFile", "Open", "OpenFile", "Walk", "WalkDir", "ReadDir", "ReadAll", "NewScanner", "NewReader"},
			QualifiedContains: []string{"os.", "io.", "bufio.", "ioutil."}, Evidence: StatusObserved,
			Note: "file and stream reads whose content is external; whether the path or the content is attacker-controlled is not established statically"},
		{Kind: SourceMessage, Suffixes: []string{".Consume", ".ConsumePartition", ".Subscribe", ".ReceiveMessage", ".Receive", ".Poll"}, Evidence: StatusObserved,
			Note: "message consumers deliver payloads an external producer controls"},
		{Kind: SourceEnv, Names: []string{"Getenv", "LookupEnv", "Environ"}, QualifiedContains: []string{"os."}, Evidence: StatusObserved,
			Note: "environment variables are external input to the process, not necessarily attacker-controlled"},
		{Kind: SourceCLIArg, Names: []string{"Arg", "Args"}, QualifiedContains: []string{"flag."}, Evidence: StatusObserved},
	}
}

// DefaultSinkRules returns the sink rules.
func DefaultSinkRules() []MatchRule {
	return []MatchRule{
		{Kind: SinkSQL, Suffixes: []string{".Query", ".QueryContext", ".QueryRow", ".QueryRowContext", ".Exec", ".ExecContext", ".Prepare", ".PrepareContext", ".NamedExec"}, Evidence: StatusObserved,
			Note: "database access; whether the statement is parameterised is recorded from the literal when there is one"},
		{Kind: SinkSQL, Names: []string{"Get", "Select", "Raw", "Where", "Find", "Model", "Joins", "Create", "Updates", "Save", "Delete", "Scan"},
			QualifiedContains: []string{"sqlx", "gorm.io", "go-pg", "pgx", "database/sql"}, Evidence: StatusObserved,
			Note: "ORM and query-builder methods, only recognised when their package is visible: these names are too generic to trust on their own"},
		{Kind: SinkFileWrite, Names: []string{"WriteFile", "Create", "OpenFile", "Remove", "RemoveAll", "Rename", "MkdirAll", "Chmod", "Truncate", "WriteString", "Sync"},
			QualifiedContains: []string{"os.", "ioutil.", "bufio."}, Evidence: StatusObserved,
			Note: "filesystem mutation; a variable path is recorded without claiming where it points"},
		{Kind: SinkProcess, Names: []string{"Command", "CommandContext", "StartProcess", "ForkExec"},
			QualifiedContains: []string{"os/exec", "syscall."}, Evidence: StatusObserved,
			Note: "process execution; argument construction and shell wrapping are not analysed"},
		{Kind: SinkProcess, Names: []string{"Exec", "Run", "RunContext", "Start"},
			QualifiedContains: []string{"syscall."}, Evidence: StatusObserved,
			Note: "process-shaped methods, only recognised inside the syscall package"},
		{Kind: SinkNetwork, Names: []string{"Get", "Post", "PostForm", "Head", "NewRequest", "NewRequestWithContext", "Do", "Dial", "DialTimeout", "DialContext", "LookupHost"},
			QualifiedContains: []string{"net/http", "net.", "grpc"}, Evidence: StatusObserved,
			Note: "outbound requests; whether the destination is attacker-influenced is not established statically"},
		{Kind: SinkDeserialization, Names: []string{"Unmarshal", "UnmarshalJSON", "Decode", "DecodeValue", "NewDecoder", "UnmarshalText"},
			QualifiedContains: []string{"encoding/json", "encoding/xml", "encoding/gob", "yaml", "msgpack", "bson", "toml"}, Evidence: StatusObserved,
			Note: "deserialisation is both a source and a sink; this rule records the operation, not the trust level of its input"},
		{Kind: SinkSensitiveOutput, NameContainsCaseInsensitive: []string{"password", "passwd", "secret", "token", "apikey", "api_key", "credential", "privatekey", "private_key"}, Heuristic: true, Evidence: StatusInferred,
			Note: "name-based heuristic: a print/log call whose arguments mention a secret-like name. It can be wrong in both directions and is kept because silently missing a secret log is worse"},
	}
}

// DefaultControlRules returns the security-control rules.
func DefaultControlRules() []MatchRule {
	return []MatchRule{
		{Kind: ControlAuthentication, Suffixes: []string{".Use", ".Pre", ".Middleware", ".Wrap"},
			NameContainsCaseInsensitive: []string{"auth", "jwt", "session", "oauth", "apikey", "api_key", "bearer", "token", "login", "basic"}, Evidence: StatusObserved,
			Note: "middleware registration whose argument mentions an authentication mechanism"},
		{Kind: ControlAuthentication, Names: []string{"BasicAuth", "SetBasicAuth", "ParseToken", "ValidateToken", "VerifyToken", "Authenticate", "CompareHashAndPassword", "ParseWithClaims", "NewJWT"},
			QualifiedContains: []string{"jwt", "oauth2", "sessions", "bcrypt", "crypto"}, Evidence: StatusObserved},
		{Kind: ControlAuthorization, Names: []string{"RequireRole", "RequirePermission", "RequireScope", "HasRole", "HasPermission", "IsAllowed", "Can"}, Evidence: StatusObserved,
			Note: "authorisation verbs that are specific enough to recognise by name"},
		{Kind: ControlAuthorization, Names: []string{"Authorize", "Enforce", "CheckPermission", "CheckAccess"},
			QualifiedContains: []string{"casbin", "rbac", "authz", "auth"}, Evidence: StatusObserved},
		{Kind: ControlInputValidation, NamePrefix: "Validate", Evidence: StatusObserved,
			Note: "validation by naming convention; whether the validated input reaches a sink is not established"},
		{Kind: ControlInputValidation, Names: []string{"Sanitize", "SanitizeInput", "Verify"},
			QualifiedContains: []string{"validator", "govalidator", "binding", "sanitize"}, Evidence: StatusObserved},
		{Kind: ControlInputValidation, Names: []string{"Struct", "Check", "Valid"}, QualifiedContains: []string{"validator", "govalidator", "binding"}, Evidence: StatusObserved},
		{Kind: ControlEncoding, Names: []string{"EscapeString", "HTMLEscapeString", "QueryEscape", "PathEscape", "HTMLEscape", "JSEscape", "Quote", "Escape"},
			QualifiedContains: []string{"html/template", "net/url", "html.", "strconv."}, Evidence: StatusObserved},
		{Kind: ControlPathNormalization, Names: []string{"Clean", "Abs", "EvalSymlinks", "Rel", "IsLocal", "FromSlash"},
			QualifiedContains: []string{"path/filepath", "path."}, Evidence: StatusObserved},
	}
}

// RulesetHash identifies the exact rule table, so an ASG built with different
// rules is never compared with an older one.
func RulesetHash(frameworks []FrameworkRule, sources, sinks, controls []MatchRule) string {
	h := sha256.New()
	fmt.Fprintf(h, "codexploit/asg/ruleset/v%d\n", SchemaVersion)
	for _, f := range append([]FrameworkRule(nil), frameworks...) {
		fields := []string{"framework", f.Name, f.EntryKind, strings.Join(f.Constructors, ","),
			strings.Join(f.RouteMethods, ","), strings.Join(f.PackageRouteFuncs, ","), fmt.Sprint(f.HandlerArgIndex)}
		for _, field := range fields {
			fmt.Fprintf(h, "%d:%s\n", len(field), field)
		}
	}
	for _, group := range [][]MatchRule{sources, sinks, controls} {
		rules := append([]MatchRule(nil), group...)
		sort.Slice(rules, func(i, j int) bool {
			if rules[i].Kind != rules[j].Kind {
				return rules[i].Kind < rules[j].Kind
			}
			return strings.Join(rules[i].Names, ",") < strings.Join(rules[j].Names, ",")
		})
		for _, r := range rules {
			fields := []string{r.Kind, strings.Join(r.Names, ","), strings.Join(r.Suffixes, ","),
				strings.Join(r.QualifiedContains, ","), r.NamePrefix, strings.Join(r.NameContainsCaseInsensitive, ","), string(r.Evidence)}
			for _, field := range fields {
				fmt.Fprintf(h, "%d:%s\n", len(field), field)
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// calleeBase returns the part of a callee text after the last dot.
func calleeBase(calleeText string) string {
	if i := strings.LastIndex(calleeText, "."); i >= 0 {
		return calleeText[i+1:]
	}
	return calleeText
}

// matches reports whether a call site matches a source, sink or control rule.
//
// The classes are ANDed and each class is ORed internally: a rule that names a
// callee and a package only matches when both hold. Anything else produces the
// false positives this design cannot afford — `db.Query` read as a request
// parameter, `os.ReadFile` read as a file write, `http.Get` read as SQL.
//
// The reasons are returned so a node can record how it was decided.
func (r MatchRule) matches(calleeText, calleeQualified string, argTexts []string) (bool, []string) {
	var reasons []string
	base := calleeBase(calleeText)

	nameClass := len(r.Names) == 0 && len(r.Suffixes) == 0 && r.NamePrefix == ""
	for _, name := range r.Names {
		if base == name {
			reasons = append(reasons, "callee name "+name)
			nameClass = true
			break
		}
	}
	if !nameClass {
		for _, suffix := range r.Suffixes {
			if strings.HasSuffix(calleeText, suffix) || strings.HasSuffix(calleeQualified, suffix) {
				reasons = append(reasons, "callee suffix "+suffix)
				nameClass = true
				break
			}
		}
	}
	if !nameClass && r.NamePrefix != "" && strings.HasPrefix(base, r.NamePrefix) {
		reasons = append(reasons, "callee name prefix "+r.NamePrefix)
		nameClass = true
	}

	qualifiedClass := len(r.QualifiedContains) == 0
	subject := calleeQualified + " " + calleeText
	for _, fragment := range r.QualifiedContains {
		if strings.Contains(subject, fragment) {
			reasons = append(reasons, "qualified name contains "+fragment)
			qualifiedClass = true
			break
		}
	}

	textClass := len(r.NameContainsCaseInsensitive) == 0
	if !textClass {
		haystack := strings.ToLower(calleeText + " " + calleeQualified + " " + strings.Join(argTexts, " "))
		for _, needle := range r.NameContainsCaseInsensitive {
			if strings.Contains(haystack, strings.ToLower(needle)) {
				reasons = append(reasons, "text mentions "+needle)
				textClass = true
				break
			}
		}
	}
	return nameClass && qualifiedClass && textClass, reasons
}
