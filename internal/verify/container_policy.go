package verify

import (
	"errors"
	"fmt"
	"strings"
)

// ContainerPolicy is the isolation the host asks the container backend for. The
// provider must either enforce every field or reject the request; a container that
// silently loses one of these guarantees is not a verification environment.
type ContainerPolicy struct {
	Image          string   `json:"image"`
	User           string   `json:"user"`
	ReadOnlyRootFS bool     `json:"read_only_root_fs"`
	Env            []string `json:"env,omitempty"`
	SourceMount    string   `json:"source_mount"`
	ScratchMB      int      `json:"scratch_mb"`
	TTLSeconds     int      `json:"ttl_seconds"`
	CPUMillis      int      `json:"cpu_millis"`
	MemoryMB       int      `json:"memory_mb"`
	PIDs           int      `json:"pids"`
	NetworkMode    string   `json:"network_mode"`
	HostSocket     bool     `json:"host_socket"`
}

var ErrContainerPolicy = errors.New("verify: the container policy is not enforced")

// ValidateContainerPolicy rejects a policy that would weaken isolation: a root
// user, a writable root filesystem, the host socket, an unbounded lifetime or a
// secret-looking environment variable.
func ValidateContainerPolicy(policy ContainerPolicy) error {
	switch {
	case strings.TrimSpace(policy.Image) == "":
		return fmt.Errorf("%w: image is required", ErrContainerPolicy)
	case strings.TrimSpace(policy.User) == "" || policy.User == "0" || strings.EqualFold(policy.User, "root"):
		return fmt.Errorf("%w: a non-root user is required", ErrContainerPolicy)
	case !policy.ReadOnlyRootFS:
		return fmt.Errorf("%w: the root filesystem must be read-only", ErrContainerPolicy)
	case policy.HostSocket:
		return fmt.Errorf("%w: the host docker socket is forbidden", ErrContainerPolicy)
	case policy.TTLSeconds <= 0:
		return fmt.Errorf("%w: a positive ttl is required", ErrContainerPolicy)
	case policy.ScratchMB <= 0 || policy.MemoryMB <= 0 || policy.CPUMillis <= 0 || policy.PIDs <= 0:
		return fmt.Errorf("%w: resource limits are required", ErrContainerPolicy)
	case policy.NetworkMode != "none" && policy.NetworkMode != "allowlist":
		return fmt.Errorf("%w: network mode must be none or allowlist", ErrContainerPolicy)
	}
	for _, entry := range policy.Env {
		key, _, found := strings.Cut(entry, "=")
		if !found || strings.TrimSpace(key) == "" {
			return fmt.Errorf("%w: environment entries must be KEY=value", ErrContainerPolicy)
		}
		upper := strings.ToUpper(key)
		for _, secret := range []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"} {
			if strings.Contains(upper, secret) {
				return fmt.Errorf("%w: environment must not carry secrets", ErrContainerPolicy)
			}
		}
	}
	return nil
}
