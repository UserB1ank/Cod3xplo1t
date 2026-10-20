package verify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// EnvironmentProvider is the domain port for a real environment backend. It is
// deliberately separate from the plugin runtime: a verifier requests an
// environment, the host provisions and later destroys it, and the verifier never
// receives a host socket or infrastructure credential.
type EnvironmentProvider interface {
	// Capabilities names what the backend can actually enforce (for example
	// "container", "network_none", "read_only_source").
	Capabilities() []string
	// Validate rejects a spec this backend cannot honour; unsupported fields must
	// not be silently ignored.
	Validate(context.Context, PlanEnvironment) error
	// Provision creates the environment and returns a receipt of the limits that
	// were actually applied.
	Provision(context.Context, EnvironmentRequest) (EnvironmentHandle, error)
	Status(context.Context, EnvironmentHandle) (EnvironmentState, error)
	Destroy(context.Context, EnvironmentHandle) error
}

var (
	ErrEnvironmentUnsupported = errors.New("verify: the environment provider cannot honour the plan")
	ErrEnvironmentNotFound    = errors.New("verify: environment not found")
	ErrEnvironmentExpired     = errors.New("verify: environment lease expired")
)

type EnvironmentState string

const (
	EnvironmentProvisioning EnvironmentState = "provisioning"
	EnvironmentReady        EnvironmentState = "ready"
	EnvironmentRunning      EnvironmentState = "running"
	EnvironmentDestroyed    EnvironmentState = "destroyed"
	EnvironmentFailed       EnvironmentState = "failed"
)

// EnvironmentRequest binds provisioning to an approved fixed plan.
type EnvironmentRequest struct {
	Plan     ExecutionPlan
	Approval PlanApproval
}

// EnvironmentHandle is the opaque reference the verifier uses. The receipt records
// what was actually enforced, not what was requested.
type EnvironmentHandle struct {
	ID        string             `json:"environment_id"`
	Provider  string             `json:"provider"`
	State     EnvironmentState   `json:"state"`
	Receipt   EnvironmentReceipt `json:"receipt"`
	ExpiresAt string             `json:"expires_at"`
}

type EnvironmentReceipt struct {
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	Provider        string   `json:"provider"`
	ProviderVersion string   `json:"provider_version"`
	Applied         []string `json:"applied"`
	NetworkMode     string   `json:"network_mode"`
	SourceReadOnly  bool     `json:"source_read_only"`
	ScratchMB       int      `json:"scratch_mb"`
	TTLSeconds      int      `json:"ttl_seconds"`
	CPUMillis       int      `json:"cpu_millis"`
	MemoryMB        int      `json:"memory_mb"`
	MaxProcesses    int      `json:"max_processes"`
	Digest          string   `json:"digest"`
}

// ValidateEnvironmentRequest checks that provisioning only happens for an
// approved plan, that the backend advertises the plan's required capabilities and
// that no secret is smuggled through a credential reference.
func ValidateEnvironmentRequest(request EnvironmentRequest, capabilities []string, now time.Time) error {
	if err := ValidateExecutionPlan(request.Plan); err != nil {
		return err
	}
	if request.Plan.NeedsApproval() {
		if err := ValidateApproval(request.Plan, request.Approval, now); err != nil {
			return err
		}
	}
	granted := map[string]bool{}
	for _, capability := range capabilities {
		granted[capability] = true
	}
	for _, capability := range request.Plan.Environment.Provider.Capabilities {
		if !granted[capability] {
			return fmt.Errorf("%w: provider lacks %q", ErrEnvironmentUnsupported, capability)
		}
	}
	for _, reference := range request.Plan.Environment.CredentialRefs {
		if strings.Contains(reference, "=") || strings.Contains(reference, "://") || len(reference) > 200 {
			return fmt.Errorf("%w: credential refs must be opaque identifiers", ErrPlanInvalid)
		}
	}
	if request.Plan.Environment.Network.Mode == "allowlist" && len(request.Plan.Environment.Network.AllowedHosts) == 0 {
		return fmt.Errorf("%w: allowlist mode needs a host", ErrPlanInvalid)
	}
	return nil
}
