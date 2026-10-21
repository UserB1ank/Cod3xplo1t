package verify

import (
	"errors"
	"testing"
)

func validContainerPolicy() ContainerPolicy {
	return ContainerPolicy{
		Image: "codexploit/verify-fixture:1.0", User: "10001:10001", ReadOnlyRootFS: true,
		SourceMount: "/source", ScratchMB: 64, TTLSeconds: 120,
		CPUMillis: 500, MemoryMB: 256, PIDs: 32, NetworkMode: "none",
	}
}

func TestValidateContainerPolicyRequiresIsolation(t *testing.T) {
	if err := ValidateContainerPolicy(validContainerPolicy()); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	cases := map[string]func(*ContainerPolicy){
		"root":          func(p *ContainerPolicy) { p.User = "root" },
		"writable root": func(p *ContainerPolicy) { p.ReadOnlyRootFS = false },
		"socket":        func(p *ContainerPolicy) { p.HostSocket = true },
		"ttl":           func(p *ContainerPolicy) { p.TTLSeconds = 0 },
		"resources":     func(p *ContainerPolicy) { p.MemoryMB = 0 },
		"network":       func(p *ContainerPolicy) { p.NetworkMode = "host" },
		"secret env":    func(p *ContainerPolicy) { p.Env = []string{"API_KEY=secret"} },
	}
	for name, change := range cases {
		policy := validContainerPolicy()
		change(&policy)
		if err := ValidateContainerPolicy(policy); !errors.Is(err, ErrContainerPolicy) {
			t.Errorf("%s = %v", name, err)
		}
	}
}
