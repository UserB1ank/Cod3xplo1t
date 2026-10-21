package verify

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestValidateEnvironmentRequestBindsApprovalAndCapabilities(t *testing.T) {
	now := time.Now().UTC()
	plan := validExecutionPlan()
	plan.Digest = plan.DigestOf()
	approval := PlanApproval{
		PlanID: plan.ID, PlanDigest: plan.DigestOf(), Decision: PlanApproved,
		Actor: "alice", ActorRole: "writer", Permissions: []string{"dynamic_exec"},
		Reason: "authorized", DecidedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	approval.Digest = approval.DigestOf()
	request := EnvironmentRequest{Plan: plan, Approval: approval}
	capabilities := []string{"container", "network_none", "read_only_source"}
	if err := ValidateEnvironmentRequest(request, capabilities, now); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	if err := ValidateEnvironmentRequest(EnvironmentRequest{Plan: plan}, capabilities, now); !errors.Is(err, ErrPlanInvalid) {
		t.Fatalf("missing approval = %v", err)
	}
	if err := ValidateEnvironmentRequest(request, []string{"network_none"}, now); !errors.Is(err, ErrEnvironmentUnsupported) {
		t.Fatalf("missing capability = %v", err)
	}
	leaky := plan
	leaky.Environment.CredentialRefs = []string{"PASSWORD=secret"}
	leaky.Digest = leaky.DigestOf()
	leakyApproval := approval
	leakyApproval.PlanDigest = leaky.DigestOf()
	leakyApproval.Digest = leakyApproval.DigestOf()
	if err := ValidateEnvironmentRequest(EnvironmentRequest{Plan: leaky, Approval: leakyApproval}, capabilities, now); !errors.Is(err, ErrPlanInvalid) {
		t.Fatalf("leaky credential ref = %v", err)
	}
}

type fakeProvider struct{}

func (fakeProvider) Capabilities() []string                          { return []string{"container"} }
func (fakeProvider) Validate(context.Context, PlanEnvironment) error { return nil }
func (fakeProvider) Provision(context.Context, EnvironmentRequest) (EnvironmentHandle, error) {
	return EnvironmentHandle{}, nil
}
func (fakeProvider) Status(context.Context, EnvironmentHandle) (EnvironmentState, error) {
	return EnvironmentReady, nil
}
func (fakeProvider) Destroy(context.Context, EnvironmentHandle) error { return nil }

func TestEnvironmentProviderPortIsImplementable(t *testing.T) {
	var provider EnvironmentProvider = fakeProvider{}
	if len(provider.Capabilities()) == 0 {
		t.Fatal("provider has no capabilities")
	}
}
