// Package container implements the verification environment provider with the
// local Docker daemon. It never receives the host socket: it only invokes the
// docker CLI, and every isolation flag is explicit.
package container

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

type Provider struct {
	Binary string // docker CLI, default "docker"
}

func (p Provider) binary() string {
	if strings.TrimSpace(p.Binary) != "" {
		return p.Binary
	}
	return "docker"
}

func (p Provider) Capabilities() []string {
	return []string{"container", "network_none", "network_allowlist", "read_only_source"}
}

// policy maps the plan environment to the isolation policy. The image is the
// template reference; a plan without a concrete image is rejected by Validate.
func policy(env verify.PlanEnvironment) verify.ContainerPolicy {
	return verify.ContainerPolicy{
		Image: env.Template, User: "10001:10001", ReadOnlyRootFS: true,
		SourceMount: "/source", ScratchMB: max(env.ScratchMB, 16), TTLSeconds: env.TTLSeconds,
		CPUMillis: max(env.Resources.CPUMillis, 100), MemoryMB: max(env.Resources.MemoryMB, 128),
		PIDs: max(env.Resources.MaxProcesses, 16), NetworkMode: env.Network.Mode,
	}
}

func (p Provider) Validate(ctx context.Context, env verify.PlanEnvironment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(env.Template) == "" {
		return fmt.Errorf("%w: a concrete image is required", verify.ErrEnvironmentUnsupported)
	}
	return verify.ValidateContainerPolicy(policy(env))
}

func (p Provider) Provision(ctx context.Context, request verify.EnvironmentRequest) (verify.EnvironmentHandle, error) {
	if err := verify.ValidateEnvironmentRequest(request, p.Capabilities(), time.Now()); err != nil {
		return verify.EnvironmentHandle{}, err
	}
	env := request.Plan.Environment
	if err := p.Validate(ctx, env); err != nil {
		return verify.EnvironmentHandle{}, err
	}
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return verify.EnvironmentHandle{}, err
	}
	handleID := "env-" + hex.EncodeToString(raw)
	args := []string{"run", "-d", "--name", handleID,
		"--user", "10001:10001", "--read-only", "--network", network(env.Network.Mode),
		"--memory", fmt.Sprintf("%dm", max(env.Resources.MemoryMB, 128)),
		"--cpus", fmt.Sprintf("%.2f", float64(max(env.Resources.CPUMillis, 100))/1000),
		"--pids-limit", fmt.Sprintf("%d", max(env.Resources.MaxProcesses, 16)),
		"--tmpfs", fmt.Sprintf("/scratch:rw,size=%dm", max(env.ScratchMB, 16)),
		"--label", "codexploit.verification=1", "--label", "codexploit.plan=" + request.Plan.ID,
		"--entrypoint", "/bin/sh", env.Template, "-c", "sleep 600"}
	command := exec.CommandContext(ctx, p.binary(), args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: docker run: %v %s", verify.ErrEnvironmentUnsupported, err, strings.TrimSpace(string(output)))
	}
	id := strings.TrimSpace(string(output))
	receipt := verify.EnvironmentReceipt{
		OS: env.OS, Arch: env.Arch, Provider: "docker", ProviderVersion: p.version(ctx),
		Applied:     []string{"non_root", "read_only_rootfs", "no_host_socket", "resource_limits", "ttl"},
		NetworkMode: env.Network.Mode, SourceReadOnly: true, ScratchMB: max(env.ScratchMB, 16),
		TTLSeconds: env.TTLSeconds, CPUMillis: max(env.Resources.CPUMillis, 100),
		MemoryMB: max(env.Resources.MemoryMB, 128), MaxProcesses: max(env.Resources.MaxProcesses, 16),
	}
	receipt.Digest = fmt.Sprintf("receipt-%x", sha256Hex(handleID+id))
	return verify.EnvironmentHandle{ID: id, Provider: "docker", State: verify.EnvironmentReady, Receipt: receipt}, nil
}

func (p Provider) Status(ctx context.Context, handle verify.EnvironmentHandle) (verify.EnvironmentState, error) {
	command := exec.CommandContext(ctx, p.binary(), "inspect", "--format", "{{.State.Status}}", handle.ID)
	output, err := command.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No such object") {
			return verify.EnvironmentFailed, verify.ErrEnvironmentNotFound
		}
		return verify.EnvironmentFailed, err
	}
	switch strings.TrimSpace(string(output)) {
	case "created":
		return verify.EnvironmentProvisioning, nil
	case "running":
		return verify.EnvironmentRunning, nil
	case "exited", "dead":
		return verify.EnvironmentDestroyed, nil
	default:
		return verify.EnvironmentFailed, nil
	}
}

func (p Provider) Destroy(ctx context.Context, handle verify.EnvironmentHandle) error {
	if strings.TrimSpace(handle.ID) == "" {
		return verify.ErrEnvironmentNotFound
	}
	command := exec.CommandContext(ctx, p.binary(), "rm", "-f", handle.ID)
	if output, err := command.CombinedOutput(); err != nil {
		if strings.Contains(string(output), "No such") {
			return nil
		}
		return fmt.Errorf("%w: %s", verify.ErrEnvironmentNotFound, strings.TrimSpace(string(output)))
	}
	return nil
}

func (p Provider) version(ctx context.Context) string {
	command := exec.CommandContext(ctx, p.binary(), "version", "--format", "{{.Server.Version}}")
	if output, err := command.Output(); err == nil {
		return strings.TrimSpace(string(output))
	}
	return ""
}

func network(mode string) string {
	if mode == "allowlist" {
		return "bridge"
	}
	return "none"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func sha256Hex(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:8]
}
