package verify

import (
	"errors"
	"fmt"
	"slices"
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
	SourceReadOnly bool     `json:"source_read_only"`
	ScratchMB      int      `json:"scratch_mb"`
	TTLSeconds     int      `json:"ttl_seconds"`
	CPUMillis      int      `json:"cpu_millis"`
	MemoryMB       int      `json:"memory_mb"`
	PIDs           int      `json:"pids"`
	NetworkMode    string   `json:"network_mode"`
	HostSocket     bool     `json:"host_socket"`
}

var ErrContainerPolicy = errors.New("verify: the container policy is not enforced")

// secretEnvironmentMarkers are the name fragments a verification container must
// never receive. Matching is on the upper-cased key so SECRET_KEY, api_token and
// DB_PASSWORD are all refused, but a value is never inspected: the policy is about
// not carrying credentials at all, not about guessing which strings look secret.
var secretEnvironmentMarkers = []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}

// ValidateContainerEnvironment checks the shape of KEY=value entries and rejects
// any name that could carry a credential. It is exported so a plan validator and a
// provider apply the same rule.
func ValidateContainerEnvironment(entries []string) error {
	seen := map[string]bool{}
	for _, entry := range entries {
		key, _, found := strings.Cut(entry, "=")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			return fmt.Errorf("%w: environment entries must be KEY=value", ErrContainerPolicy)
		}
		if seen[key] {
			return fmt.Errorf("%w: environment key %q is repeated", ErrContainerPolicy, key)
		}
		seen[key] = true
		upper := strings.ToUpper(key)
		for _, secret := range secretEnvironmentMarkers {
			if strings.Contains(upper, secret) {
				return fmt.Errorf("%w: environment key %q looks like a credential; pass a credential ref instead", ErrContainerPolicy, key)
			}
		}
	}
	return nil
}

// ValidateContainerPolicy rejects a policy that would weaken isolation: a root
// user, a writable root filesystem, a writable source tree, the host socket, an
// unbounded lifetime or a secret-looking environment variable.
func ValidateContainerPolicy(policy ContainerPolicy) error {
	switch {
	case strings.TrimSpace(policy.Image) == "":
		return fmt.Errorf("%w: image is required", ErrContainerPolicy)
	case strings.TrimSpace(policy.User) == "" || policy.User == "0" || strings.Contains(policy.User, "root"):
		return fmt.Errorf("%w: a non-root user is required", ErrContainerPolicy)
	case !policy.ReadOnlyRootFS:
		return fmt.Errorf("%w: the root filesystem must be read-only", ErrContainerPolicy)
	case strings.TrimSpace(policy.SourceMount) == "":
		return fmt.Errorf("%w: a read-only source mount is required", ErrContainerPolicy)
	case !policy.SourceReadOnly:
		return fmt.Errorf("%w: the source tree must be mounted read-only", ErrContainerPolicy)
	case policy.HostSocket:
		return fmt.Errorf("%w: the host docker socket is forbidden", ErrContainerPolicy)
	case policy.TTLSeconds <= 0:
		return fmt.Errorf("%w: a positive ttl is required", ErrContainerPolicy)
	case policy.ScratchMB <= 0 || policy.MemoryMB <= 0 || policy.CPUMillis <= 0 || policy.PIDs <= 0:
		return fmt.Errorf("%w: resource limits are required", ErrContainerPolicy)
	case policy.NetworkMode != "none" && policy.NetworkMode != "allowlist":
		return fmt.Errorf("%w: network mode must be none or allowlist", ErrContainerPolicy)
	}
	if slices.Contains(strings.Split(policy.SourceMount, "/"), "docker.sock") {
		return fmt.Errorf("%w: the source mount must not reach the docker socket", ErrContainerPolicy)
	}
	if strings.Contains(strings.ToLower(policy.Image), "docker.sock") {
		return fmt.Errorf("%w: the image must not be a socket path", ErrContainerPolicy)
	}
	return ValidateContainerEnvironment(policy.Env)
}
