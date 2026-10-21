package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ExecutionPlanSchemaVersion is the versioned verification plan that binds the
// hypothesis, the verifier, the assertions, the environment and the authorization
// before a dynamic run may start. The older v1 Plan remains readable; a new plan is
// always written as v2 so its approval cannot be confused with a v1 hash.
const ExecutionPlanSchemaVersion = 2

// PlanState is the approval lifecycle of a fixed plan.
type PlanState string

const (
	PlanPending     PlanState = "pending"
	PlanApproved    PlanState = "approved"
	PlanRejected    PlanState = "rejected"
	PlanInvalidated PlanState = "invalidated"
	PlanUnsupported PlanState = "unsupported"
)

var (
	ErrPlanInvalid     = errors.New("verify: invalid execution plan")
	ErrPlanNotApproved = errors.New("verify: the plan is not approved")
	ErrPlanStale       = errors.New("verify: the approval does not match the current plan")
	ErrPlanExpired     = errors.New("verify: the approval has expired")
	ErrPlanExpanded    = errors.New("verify: the approval exceeds the plan's permissions")
)

// CanTransition reports whether a plan state may move to another. An approval is
// single-use for execution; any semantic change invalidates it.
func (s PlanState) CanTransition(to PlanState) bool {
	switch s {
	case PlanPending:
		return to == PlanApproved || to == PlanRejected || to == PlanUnsupported || to == PlanInvalidated
	case PlanApproved:
		return to == PlanInvalidated
	case PlanRejected:
		return to == PlanInvalidated
	case PlanUnsupported:
		return to == PlanInvalidated
	}
	return false
}

// PlanProvider names the environment backend separate from the plugin runtime.
type PlanProvider struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type PlanResources struct {
	CPUMillis    int `json:"cpu_millis"`
	MemoryMB     int `json:"memory_mb"`
	DiskMB       int `json:"disk_mb"`
	MaxProcesses int `json:"max_processes"`
	MaxWrites    int `json:"max_writes"`
}

type ReadinessProbe struct {
	Kind            string   `json:"kind"`
	Command         []string `json:"command,omitempty"`
	Path            string   `json:"path,omitempty"`
	Port            int      `json:"port,omitempty"`
	TimeoutSeconds  int      `json:"timeout_seconds,omitempty"`
	IntervalSeconds int      `json:"interval_seconds,omitempty"`
}

type ServiceSpec struct {
	Name      string           `json:"name"`
	Role      string           `json:"role"`
	Template  string           `json:"template"`
	DependsOn []string         `json:"depends_on,omitempty"`
	Readiness []ReadinessProbe `json:"readiness,omitempty"`
	// Command is the argv the environment starts for this service. Like a step
	// command it is an argv, never a shell string.
	Command []string `json:"command,omitempty"`
	// Workdir is the directory the service starts in. It must stay inside the
	// read-only source mount, which is where /source resolves.
	Workdir string `json:"workdir,omitempty"`
}

type NetworkRule struct {
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	Host      string `json:"host,omitempty"`
	Port      string `json:"port,omitempty"`
}

type PlanNetwork struct {
	Mode         string        `json:"mode"`
	AllowedHosts []string      `json:"allowed_hosts,omitempty"`
	Rules        []NetworkRule `json:"rules,omitempty"`
}

type PlanEnvironment struct {
	OS             string        `json:"os"`
	Arch           string        `json:"arch"`
	Provider       PlanProvider  `json:"provider"`
	Template       string        `json:"template"`
	Inputs         []string      `json:"inputs,omitempty"`
	Services       []ServiceSpec `json:"services,omitempty"`
	Network        PlanNetwork   `json:"network"`
	SourceReadOnly bool          `json:"source_read_only"`
	ScratchMB      int           `json:"scratch_mb"`
	TTLSeconds     int           `json:"ttl_seconds"`
	Permissions    []string      `json:"permissions,omitempty"`
	CredentialRefs []string      `json:"credential_refs,omitempty"`
	Resources      PlanResources `json:"resources"`
	// Env is the non-secret environment the service receives. A key that looks
	// like a credential is rejected by ValidateContainerPolicy rather than passed
	// to the container; secrets travel through credential refs.
	Env []string `json:"env,omitempty"`
}

type PlanVerifier struct {
	Adapter    string `json:"adapter"`
	Version    string `json:"version"`
	Capability string `json:"capability"`
}

type PlanAssertion struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Expectation   string   `json:"expectation"`
	Contradiction string   `json:"contradiction"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty"`
	Required      bool     `json:"required"`
}

type PlanBudget struct {
	MaxSeconds  int `json:"max_seconds"`
	MaxSteps    int `json:"max_steps"`
	MaxCommands int `json:"max_commands"`
}

// ExecutionPlan is the fixed, reviewable v2 plan. Its normalised digest covers
// every field that changes what would run or what would be claimed.
type ExecutionPlan struct {
	SchemaVersion int             `json:"schema_version"`
	ID            string          `json:"plan_id"`
	ProjectID     string          `json:"project_id"`
	HypothesisID  string          `json:"hypothesis_id"`
	FindingID     string          `json:"finding_id,omitempty"`
	PathID        string          `json:"path_id"`
	AuditID       string          `json:"audit_id"`
	SnapshotID    string          `json:"snapshot_id"`
	KnowledgePin  string          `json:"knowledge_pin,omitempty"`
	SecurityGoal  string          `json:"security_goal"`
	Claim         string          `json:"claim"`
	Verifier      PlanVerifier    `json:"verifier"`
	Steps         []Step          `json:"steps"`
	Assertions    []PlanAssertion `json:"assertions"`
	Environment   PlanEnvironment `json:"environment"`
	Scope         Scope           `json:"scope"`
	Budget        PlanBudget      `json:"budget"`
	Limitations   []string        `json:"limitations,omitempty"`
	CreatedAt     string          `json:"created_at"`
	ExpiresAt     string          `json:"expires_at"`
	Digest        string          `json:"digest"`
}

// DecodeExecutionPlan rejects unknown fields instead of silently dropping an
// unsupported environment or assertion field.
func DecodeExecutionPlan(raw []byte) (ExecutionPlan, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var plan ExecutionPlan
	if err := decoder.Decode(&plan); err != nil {
		return ExecutionPlan{}, fmt.Errorf("%w: %v", ErrPlanInvalid, err)
	}
	if decoder.Decode(new(any)) == nil {
		return ExecutionPlan{}, fmt.Errorf("%w: trailing content", ErrPlanInvalid)
	}
	return plan, nil
}

// PlanDigest canonicalises every execution-relevant field. IDs that only name the
// record (plan id, created_at) are excluded; the digest itself is excluded.
func (p ExecutionPlan) DigestOf() string {
	copy := p
	copy.ID, copy.CreatedAt, copy.Digest = "", "", ""
	canonical, err := json.Marshal(copy)
	if err != nil {
		return ""
	}
	return "plan-" + hex.EncodeToString(sha256Bytes(canonical)[:12])
}

func sha256Bytes(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// ValidatePlan checks the structural and authorization invariants before a plan
// may be approved. Unsupported environment fields are rejected by Decode; this
// checks that the supported ones are complete and coherent.
func ValidateExecutionPlan(plan ExecutionPlan) error {
	switch {
	case plan.SchemaVersion != ExecutionPlanSchemaVersion:
		return fmt.Errorf("%w: schema_version must be %d", ErrPlanInvalid, ExecutionPlanSchemaVersion)
	case strings.TrimSpace(plan.ID) == "" || strings.TrimSpace(plan.ProjectID) == "" || strings.TrimSpace(plan.HypothesisID) == "" ||
		strings.TrimSpace(plan.PathID) == "" || strings.TrimSpace(plan.SnapshotID) == "":
		return fmt.Errorf("%w: missing plan identity", ErrPlanInvalid)
	case strings.TrimSpace(plan.SecurityGoal) == "" || strings.TrimSpace(plan.Claim) == "":
		return fmt.Errorf("%w: missing goal or claim", ErrPlanInvalid)
	case strings.TrimSpace(plan.Verifier.Adapter) == "" || strings.TrimSpace(plan.Verifier.Version) == "":
		return fmt.Errorf("%w: missing verifier identity", ErrPlanInvalid)
	case len(plan.Steps) == 0:
		return fmt.Errorf("%w: the plan has no steps", ErrPlanInvalid)
	}
	env := plan.Environment
	switch {
	case strings.TrimSpace(env.OS) == "" || strings.TrimSpace(env.Arch) == "":
		return fmt.Errorf("%w: environment os/arch is required", ErrPlanInvalid)
	case strings.TrimSpace(env.Provider.Name) == "" || strings.TrimSpace(env.Provider.Version) == "":
		return fmt.Errorf("%w: environment provider is required", ErrPlanInvalid)
	case strings.TrimSpace(env.Template) == "":
		return fmt.Errorf("%w: environment template is required", ErrPlanInvalid)
	case env.Network.Mode != "none" && env.Network.Mode != "allowlist":
		return fmt.Errorf("%w: network mode must be none or allowlist", ErrPlanInvalid)
	case env.TTLSeconds <= 0:
		return fmt.Errorf("%w: environment ttl is required", ErrPlanInvalid)
	case env.ScratchMB <= 0:
		return fmt.Errorf("%w: a positive scratch budget is required", ErrPlanInvalid)
	case env.Resources.CPUMillis <= 0 || env.Resources.MemoryMB <= 0 || env.Resources.MaxProcesses <= 0:
		return fmt.Errorf("%w: explicit cpu, memory and process limits are required", ErrPlanInvalid)
	}
	if err := ValidateContainerEnvironment(env.Env); err != nil {
		return fmt.Errorf("%w: %v", ErrPlanInvalid, err)
	}
	if err := validatePlanServices(env.Services); err != nil {
		return err
	}
	if !env.SourceReadOnly {
		for _, step := range plan.Steps {
			if step.Kind == StepDynamicProof {
				return fmt.Errorf("%w: dynamic execution requires a read-only source mount", ErrPlanInvalid)
			}
		}
	}
	if env.Network.Mode == "none" && len(env.Network.AllowedHosts) > 0 {
		return fmt.Errorf("%w: allowed hosts require allowlist mode", ErrPlanInvalid)
	}
	if plan.Scope.SnapshotID != "" && plan.Scope.SnapshotID != plan.SnapshotID {
		return fmt.Errorf("%w: scope snapshot differs from the plan snapshot", ErrPlanInvalid)
	}
	if !plan.Scope.AllowNetwork && env.Network.Mode != "none" {
		return fmt.Errorf("%w: the environment allows network the scope does not", ErrPlanInvalid)
	}
	if plan.Budget.MaxSeconds <= 0 || plan.Budget.MaxSteps <= 0 {
		return fmt.Errorf("%w: a positive budget is required", ErrPlanInvalid)
	}
	for _, assertion := range plan.Assertions {
		if strings.TrimSpace(assertion.ID) == "" || strings.TrimSpace(assertion.Expectation) == "" || strings.TrimSpace(assertion.Contradiction) == "" {
			return fmt.Errorf("%w: assertions need id, expectation and contradiction", ErrPlanInvalid)
		}
	}
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		return fmt.Errorf("%w: expires_at must be a future RFC3339 time", ErrPlanInvalid)
	}
	if plan.Digest != "" && plan.Digest != plan.DigestOf() {
		return fmt.Errorf("%w: digest does not match the plan", ErrPlanInvalid)
	}
	return nil
}

// validatePlanServices checks the service topology before it reaches a provider.
// A plan with more than one service is structurally valid, but a provider that
// cannot honour the topology must reject it rather than start only the first one.
func validatePlanServices(services []ServiceSpec) error {
	names := map[string]bool{}
	for _, service := range services {
		name := strings.TrimSpace(service.Name)
		if name == "" || strings.TrimSpace(service.Template) == "" || strings.TrimSpace(service.Role) == "" {
			return fmt.Errorf("%w: every service needs a name, role and template", ErrPlanInvalid)
		}
		if names[name] {
			return fmt.Errorf("%w: service %q is declared twice", ErrPlanInvalid, name)
		}
		names[name] = true
		if len(service.Command) == 0 {
			return fmt.Errorf("%w: service %q has no start command", ErrPlanInvalid, name)
		}
		if service.Workdir != "" && !strings.HasPrefix(service.Workdir, "/") {
			return fmt.Errorf("%w: service %q workdir must be absolute", ErrPlanInvalid, name)
		}
		for _, probe := range service.Readiness {
			switch probe.Kind {
			case "command":
				if len(probe.Command) == 0 {
					return fmt.Errorf("%w: service %q has a command probe without a command", ErrPlanInvalid, name)
				}
			case "http", "tcp":
				if probe.Path == "" && probe.Port == 0 {
					return fmt.Errorf("%w: service %q has a network probe without a path or port", ErrPlanInvalid, name)
				}
			default:
				return fmt.Errorf("%w: service %q has unknown readiness kind %q", ErrPlanInvalid, name, probe.Kind)
			}
		}
	}
	for _, service := range services {
		for _, dependency := range service.DependsOn {
			if !names[dependency] {
				return fmt.Errorf("%w: service %q depends on unknown service %q", ErrPlanInvalid, service.Name, dependency)
			}
		}
	}
	return nil
}

// PlanApproval is the human decision that binds a fixed plan, the trusted actor,
// the permissions and the expiry. The approval digest covers the plan digest too,
// so reusing an approval for a changed plan is rejected.
type PlanApproval struct {
	PlanID      string    `json:"plan_id"`
	PlanDigest  string    `json:"plan_digest"`
	Decision    PlanState `json:"decision"`
	Actor       string    `json:"actor"`
	ActorRole   string    `json:"actor_role"`
	Permissions []string  `json:"permissions,omitempty"`
	Reason      string    `json:"reason"`
	DecidedAt   string    `json:"decided_at"`
	ExpiresAt   string    `json:"expires_at"`
	Digest      string    `json:"digest"`
}

// DigestOf computes the approval digest from the decision semantics.
func (a PlanApproval) DigestOf() string {
	copy := a
	copy.Digest = ""
	canonical, err := json.Marshal(copy)
	if err != nil {
		return ""
	}
	return "approval-" + hex.EncodeToString(sha256Bytes(canonical)[:12])
}

// ValidateApproval checks the decision against the current plan and clock. It
// rejects a stale plan digest, an untrusted actor, an expired decision and a
// permission set that exceeds what the plan requested.
func ValidateApproval(plan ExecutionPlan, approval PlanApproval, now time.Time) error {
	if approval.Decision != PlanApproved && approval.Decision != PlanRejected {
		return fmt.Errorf("%w: decision must be approved or rejected", ErrPlanInvalid)
	}
	if approval.PlanID != plan.ID || approval.PlanDigest != plan.DigestOf() {
		return ErrPlanStale
	}
	if strings.TrimSpace(approval.Actor) == "" || strings.TrimSpace(approval.ActorRole) == "" {
		return fmt.Errorf("%w: the approval needs a trusted actor and role", ErrPlanInvalid)
	}
	if strings.TrimSpace(approval.Reason) == "" {
		return fmt.Errorf("%w: the approval needs a reason", ErrPlanInvalid)
	}
	expires, err := time.Parse(time.RFC3339, approval.ExpiresAt)
	if err != nil || !expires.After(now) {
		return ErrPlanExpired
	}
	requested := map[string]bool{}
	for _, permission := range plan.Environment.Permissions {
		requested[permission] = true
	}
	for _, permission := range approval.Permissions {
		if !requested[permission] {
			return ErrPlanExpanded
		}
	}
	if approval.Digest != "" && approval.Digest != approval.DigestOf() {
		return fmt.Errorf("%w: approval digest does not match", ErrPlanInvalid)
	}
	return nil
}

// ApplyApproval returns the approved plan and state, or a rejection. It never
// upgrades a plan silently: an invalid or stale decision is an error.
func ApplyApproval(plan ExecutionPlan, approval PlanApproval, now time.Time) (ExecutionPlan, PlanState, error) {
	if err := ValidateExecutionPlan(plan); err != nil {
		return plan, PlanPending, err
	}
	if err := ValidateApproval(plan, approval, now); err != nil {
		return plan, PlanPending, err
	}
	state := PlanApproved
	if approval.Decision == PlanRejected {
		state = PlanRejected
	}
	plan.Digest = plan.DigestOf()
	return plan, state, nil
}

// PlanPermissionsEqual reports whether two permission sets are the same, ignoring
// order and duplicates; the approval cannot widen them.
func PlanPermissionsEqual(a, b []string) bool {
	normalise := func(values []string) []string {
		seen := map[string]bool{}
		result := make([]string, 0, len(values))
		for _, value := range values {
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			result = append(result, value)
		}
		sort.Strings(result)
		return result
	}
	return strings.Join(normalise(a), "\x00") == strings.Join(normalise(b), "\x00")
}

// NeedsApproval reports whether the v2 plan includes a dynamic or explicitly
// approval-gated step, or a scope that requires human approval.
func (p ExecutionPlan) NeedsApproval() bool {
	if p.Scope.RequiresHumanApproval {
		return true
	}
	for _, step := range p.Steps {
		if step.RequiresApproval || step.Kind == StepDynamicProof {
			return true
		}
	}
	return false
}

// LegacyPlan projects a fixed v2 execution plan onto the v1 Plan shape the
// existing verifier, finding merge and evidence store already understand. The
// projection is lossless where it matters: the v2 digest is carried in
// SourcePlanDigest, so two v2 plans cannot be mistaken for the same verification
// just because their commands happen to match.
func LegacyPlan(plan ExecutionPlan) Plan { return LegacyPlanAttempt(plan, 1) }

// LegacyPlanAttempt is LegacyPlan for one execution attempt. A later attempt is a
// new run with its own plan hash, so a blocked or lost attempt cannot be replayed
// as the answer to a fresh attempt.
func LegacyPlanAttempt(plan ExecutionPlan, attempt int) Plan {
	findingID := plan.FindingID
	if findingID == "" {
		findingID = FindingID(plan.HypothesisID)
	}
	steps := make([]Step, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		steps = append(steps, Step{
			Kind: step.Kind, Command: append([]string(nil), step.Command...),
			StaticQuery: step.StaticQuery, Expectation: step.Expectation,
			Contradiction: step.Contradiction, TimeoutSeconds: step.TimeoutSeconds,
			RequiresApproval: step.RequiresApproval,
		})
	}
	network := NetworkNone
	allowed := []string(nil)
	if plan.Environment.Network.Mode == "allowlist" {
		network = NetworkRestricted
		allowed = append([]string(nil), plan.Environment.Network.AllowedHosts...)
	}
	legacy := Plan{
		SchemaVersion: SchemaVersion,
		HypothesisID:  plan.HypothesisID, FindingID: findingID, PathID: plan.PathID,
		AuditID: plan.AuditID, SnapshotID: plan.SnapshotID,
		SecurityGoal: plan.SecurityGoal, Claim: plan.Claim, Steps: steps,
		Environment: Environment{
			Profile: "container:" + plan.Environment.Template, SourceReadOnly: plan.Environment.SourceReadOnly,
			Network: network, AllowedHosts: allowed,
			CPUMillis: plan.Environment.Resources.CPUMillis, MemoryMB: plan.Environment.Resources.MemoryMB,
			DiskMB: plan.Environment.Resources.DiskMB, MaxProcesses: plan.Environment.Resources.MaxProcesses,
			MaxWrites: plan.Environment.Resources.MaxWrites, TimeoutSeconds: plan.Budget.MaxSeconds,
			MountHostSocket: false,
		},
		Scope: Scope{
			Repository: plan.Scope.Repository, SnapshotID: plan.Scope.SnapshotID,
			AllowedTargets: append([]string(nil), plan.Scope.AllowedTargets...),
			AllowNetwork:   plan.Scope.AllowNetwork, RequiresHumanApproval: plan.Scope.RequiresHumanApproval,
			AuthorizedBy: plan.Scope.AuthorizedBy, AuthorizedAt: plan.Scope.AuthorizedAt,
		},
		Limitations:      append([]string(nil), plan.Limitations...),
		GeneratedAt:      plan.CreatedAt,
		SourcePlanDigest: plan.DigestOf(),
	}
	if attempt > 1 {
		legacy.SourcePlanDigest = fmt.Sprintf("%s#attempt-%d", legacy.SourcePlanDigest, attempt)
	}
	legacy.PlanHash = PlanHashOf(legacy)
	return legacy
}
