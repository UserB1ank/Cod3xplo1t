// Package container implements the verification environment provider with the
// local Docker daemon. It never receives the host socket: it only invokes the
// docker CLI, and every isolation flag is explicit.
package container

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// DefaultUser is the unprivileged identity every verification container runs as.
// The image's own user is deliberately ignored.
const DefaultUser = "10001:10001"

// Provider is the Docker implementation of verify.EnvironmentProvider.
type Provider struct {
	Binary string // docker CLI, default "docker"
	// Now is injectable so an expiration test does not sleep.
	Now func() time.Time
}

func (p Provider) binary() string {
	if strings.TrimSpace(p.Binary) != "" {
		return p.Binary
	}
	return "docker"
}

func (p Provider) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func (p Provider) Capabilities() []string {
	return []string{
		"container", "network_none", "read_only_source",
		"controlled_exec", "environment_logs",
	}
}

// policy maps the plan environment to the isolation policy. The image is the
// template reference; a plan without a concrete image is rejected by Validate.
func policy(env verify.PlanEnvironment, source verify.EnvironmentSource) verify.ContainerPolicy {
	return verify.ContainerPolicy{
		Image: env.Template, User: DefaultUser, ReadOnlyRootFS: true,
		Env:         append([]string(nil), env.Env...),
		SourceMount: "/source", SourceReadOnly: source.ReadOnly,
		ScratchMB: max(env.ScratchMB, 16), TTLSeconds: env.TTLSeconds,
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
	if env.Network.Mode == "allowlist" {
		// Docker's bridge is not an allowlist: it reaches the whole network. A
		// backend that cannot enforce the rule must refuse, never silently widen it.
		return fmt.Errorf("%w: this provider only enforces network mode none; allowlist needs a backend that can enforce the host list", verify.ErrEnvironmentUnsupported)
	}
	if len(env.Services) > 1 {
		return fmt.Errorf("%w: this provider runs one service; %d were requested", verify.ErrEnvironmentUnsupported, len(env.Services))
	}
	return verify.ValidateContainerPolicy(policy(env, verify.EnvironmentSource{ReadOnly: env.SourceReadOnly}))
}

// Provision creates the container and then reads its actual configuration back.
// The receipt is built from the daemon's answer, not from the request: a flag the
// daemon dropped must fail provisioning, not disappear into a claim.
func (p Provider) Provision(ctx context.Context, request verify.EnvironmentRequest) (verify.EnvironmentHandle, error) {
	if err := verify.ValidateEnvironmentRequest(request, p.Capabilities(), p.now()); err != nil {
		return verify.EnvironmentHandle{}, err
	}
	if err := p.Validate(ctx, request.Plan.Environment); err != nil {
		return verify.EnvironmentHandle{}, err
	}
	source := request.Source
	if strings.TrimSpace(source.Path) == "" {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: a read-only source directory is required", verify.ErrEnvironmentUnsupported)
	}
	info, err := os.Stat(source.Path)
	if err != nil || !info.IsDir() {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: source directory is not readable: %v", verify.ErrEnvironmentUnsupported, err)
	}
	if strings.TrimSpace(source.Digest) == "" {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: the source digest is required", verify.ErrEnvironmentUnsupported)
	}
	if observed, err := DigestSource(source.Path); err != nil {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: the source could not be hashed: %v", verify.ErrEnvironmentUnsupported, err)
	} else if observed != source.Digest {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: the source tree does not match the digest the plan bound", verify.ErrEnvironmentUnsupported)
	}
	env := request.Plan.Environment
	containerPolicy := policy(env, source)
	if err := verify.ValidateContainerPolicy(containerPolicy); err != nil {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: %v", verify.ErrEnvironmentUnsupported, err)
	}
	requestDigest := environmentRequestDigest(request)
	if existing, found, err := p.findByIdentity(ctx, requestDigest, runSpec{
		Policy: containerPolicy, SourcePath: source.Path, SourceDigest: source.Digest,
		RequestDigest: requestDigest, PlanID: request.Plan.ID, ProjectID: request.Plan.ProjectID,
		Owner: request.Owner, Command: serviceCommand(env), ExpiresAt: p.now().Add(time.Duration(env.TTLSeconds) * time.Second),
	}); err != nil {
		return verify.EnvironmentHandle{}, err
	} else if found {
		return existing, nil
	}
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return verify.EnvironmentHandle{}, err
	}
	handleID := "env-" + hex.EncodeToString(raw)
	spec := runSpec{
		Name: handleID, Policy: containerPolicy, SourcePath: source.Path,
		SourceDigest: source.Digest, RequestDigest: requestDigest,
		PlanID: request.Plan.ID, ProjectID: request.Plan.ProjectID, Owner: request.Owner,
		Command: serviceCommand(env), ExpiresAt: p.now().Add(time.Duration(env.TTLSeconds) * time.Second),
	}
	command := exec.CommandContext(ctx, p.binary(), runArgs(spec)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: docker run: %v %s", verify.ErrEnvironmentUnsupported, err, strings.TrimSpace(string(output)))
	}
	containerID := strings.TrimSpace(string(output))
	if containerID == "" {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: docker run returned no container id", verify.ErrEnvironmentUnsupported)
	}
	handle, err := p.verifyApplied(ctx, containerID, spec)
	if err != nil {
		_ = p.Destroy(context.WithoutCancel(ctx), verify.EnvironmentHandle{ID: containerID})
		return verify.EnvironmentHandle{}, err
	}
	return handle, nil
}

// verifyApplied reads the container configuration back from Docker and turns it
// into a receipt. Every guarantee the provider advertises must be visible there;
// otherwise provisioning fails and the container is destroyed.
func (p Provider) verifyApplied(ctx context.Context, containerID string, spec runSpec) (verify.EnvironmentHandle, error) {
	inspected, err := p.inspect(ctx, containerID)
	if err != nil {
		return verify.EnvironmentHandle{}, err
	}
	applied := []string{}
	problems := []string{}
	if inspected.Config.User != spec.Policy.User {
		problems = append(problems, fmt.Sprintf("user is %q, want %q", inspected.Config.User, spec.Policy.User))
	} else {
		applied = append(applied, "non_root")
	}
	if !inspected.HostConfig.ReadonlyRootfs {
		problems = append(problems, "the root filesystem is writable")
	} else {
		applied = append(applied, "read_only_rootfs")
	}
	if inspected.HostConfig.NetworkMode != "none" {
		problems = append(problems, fmt.Sprintf("network mode is %q, want none", inspected.HostConfig.NetworkMode))
	} else {
		applied = append(applied, "network_none")
	}
	if inspected.HostConfig.Memory != int64(spec.Policy.MemoryMB)<<20 {
		problems = append(problems, fmt.Sprintf("memory limit is %d, want %d", inspected.HostConfig.Memory, int64(spec.Policy.MemoryMB)<<20))
	} else {
		applied = append(applied, "memory_limit")
	}
	if inspected.HostConfig.NanoCpus != int64(spec.Policy.CPUMillis)*1_000_000 {
		problems = append(problems, fmt.Sprintf("cpu limit is %d, want %d", inspected.HostConfig.NanoCpus, int64(spec.Policy.CPUMillis)*1_000_000))
	} else {
		applied = append(applied, "cpu_limit")
	}
	if inspected.HostConfig.PidsLimit == nil || *inspected.HostConfig.PidsLimit != int64(spec.Policy.PIDs) {
		problems = append(problems, "the process limit was not applied")
	} else {
		applied = append(applied, "pids_limit")
	}
	if !hasCapDropAll(inspected.HostConfig.CapDrop) {
		problems = append(problems, "capabilities were not dropped")
	} else {
		applied = append(applied, "cap_drop_all")
	}
	if !hasNoNewPrivileges(inspected.HostConfig.SecurityOpt) {
		problems = append(problems, "no-new-privileges was not applied")
	} else {
		applied = append(applied, "no_new_privileges")
	}
	source, ok := findMount(inspected.Mounts, "/source")
	if !ok || source.RW || source.Source != spec.SourcePath {
		problems = append(problems, "the source tree is not mounted read-only")
	} else {
		applied = append(applied, "read_only_source")
	}
	if hasSocketMount(inspected.Mounts) {
		problems = append(problems, "the host docker socket is mounted")
	} else {
		applied = append(applied, "no_host_socket")
	}
	scratch, ok := inspected.HostConfig.Tmpfs["/scratch"]
	if !ok || !strings.Contains(scratch, fmt.Sprintf("size=%dm", spec.Policy.ScratchMB)) {
		problems = append(problems, "the scratch tmpfs was not applied")
	} else {
		applied = append(applied, "scratch_tmpfs")
	}
	if strings.TrimSpace(inspected.Image) == "" {
		problems = append(problems, "the image digest is unknown")
	}
	if len(problems) > 0 {
		return verify.EnvironmentHandle{}, fmt.Errorf("%w: docker did not apply the policy: %s", verify.ErrEnvironmentUnsupported, strings.Join(problems, "; "))
	}
	expires := p.now().Add(time.Duration(spec.Policy.TTLSeconds) * time.Second)
	imageOS, imageArch := p.imagePlatform(ctx, inspected.Image)
	receipt := verify.EnvironmentReceipt{
		OS: imageOS, Arch: imageArch, Provider: "docker", User: spec.Policy.User,
		ProviderVersion: p.version(ctx),
		Applied:         append(applied, "ttl"),
		NetworkMode:     inspected.HostConfig.NetworkMode, SourceReadOnly: !source.RW,
		SourceDigest: spec.SourceDigest, ImageDigest: inspected.Image,
		EnvironmentID: containerID, ScratchMB: spec.Policy.ScratchMB,
		TTLSeconds: spec.Policy.TTLSeconds, CPUMillis: spec.Policy.CPUMillis,
		MemoryMB: spec.Policy.MemoryMB, MaxProcesses: spec.Policy.PIDs,
	}
	if receipt.OS == "" {
		receipt.OS = "linux"
	}
	if receipt.Arch == "" {
		receipt.Arch = "amd64"
	}
	receipt.Digest = receiptDigest(receipt, spec.RequestDigest)
	return verify.EnvironmentHandle{
		ID: containerID, Provider: "docker", State: verify.EnvironmentReady,
		Receipt: receipt, ExpiresAt: expires.Format(time.RFC3339),
	}, nil
}

func (p Provider) Status(ctx context.Context, handle verify.EnvironmentHandle) (verify.EnvironmentState, error) {
	if expired(handle, p.now()) {
		return verify.EnvironmentFailed, verify.ErrEnvironmentExpired
	}
	inspected, err := p.inspect(ctx, handle.ID)
	if err != nil {
		if strings.Contains(err.Error(), "No such object") || strings.Contains(err.Error(), "not found") {
			return verify.EnvironmentFailed, verify.ErrEnvironmentNotFound
		}
		return verify.EnvironmentFailed, err
	}
	switch inspected.State.Status {
	case "created":
		return verify.EnvironmentProvisioning, nil
	case "running":
		return verify.EnvironmentRunning, nil
	case "exited", "dead", "removing":
		return verify.EnvironmentDestroyed, nil
	default:
		return verify.EnvironmentFailed, nil
	}
}

// Exec runs one controlled argv inside the container. The command is bounded by
// the same identity, filesystem and network as the service.
func (p Provider) Exec(ctx context.Context, handle verify.EnvironmentHandle, request verify.CommandRequest) (verify.CommandResult, error) {
	if strings.TrimSpace(handle.ID) == "" {
		return verify.CommandResult{}, verify.ErrEnvironmentNotFound
	}
	if expired(handle, p.now()) {
		return verify.CommandResult{}, verify.ErrEnvironmentExpired
	}
	if len(request.Argv) == 0 {
		return verify.CommandResult{}, fmt.Errorf("%w: an argv is required", verify.ErrEnvironmentUnsupported)
	}
	if request.TimeoutSeconds < 0 {
		return verify.CommandResult{}, fmt.Errorf("%w: a negative timeout is not a budget", verify.ErrEnvironmentUnsupported)
	}
	runCtx := ctx
	var cancel context.CancelFunc
	if request.TimeoutSeconds > 0 {
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(request.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	user := handle.Receipt.User
	if user == "" {
		user = DefaultUser
	}
	args := []string{"exec", "--user", user}
	if strings.TrimSpace(request.Workdir) != "" {
		args = append(args, "--workdir", request.Workdir)
	}
	args = append(args, handle.ID)
	args = append(args, request.Argv...)
	limit := request.MaxOutputBytes
	if limit <= 0 {
		limit = 256 << 10
	}
	stdout, stderr := newCappedBuffer(limit), newCappedBuffer(limit)
	command := exec.CommandContext(runCtx, p.binary(), args...)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	result := verify.CommandResult{
		Stdout: stdout.String(), Stderr: stderr.String(),
		Truncated: stdout.truncated || stderr.truncated,
		Discarded: stdout.discarded + stderr.discarded,
	}
	if runCtx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
	} else if ctx.Err() != nil {
		result.Cancelled = true
	} else if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.Err = err.Error()
		}
	}
	return result, nil
}

// Logs returns a bounded tail of the container log. A log read is evidence, so it
// is capped rather than allowed to grow with the service.
func (p Provider) Logs(ctx context.Context, handle verify.EnvironmentHandle, tail int) (string, error) {
	if strings.TrimSpace(handle.ID) == "" {
		return "", verify.ErrEnvironmentNotFound
	}
	if tail <= 0 || tail > 1000 {
		tail = 200
	}
	command := exec.CommandContext(ctx, p.binary(), "logs", "--tail", strconv.Itoa(tail), handle.ID)
	output, err := command.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No such") {
			return "", verify.ErrEnvironmentNotFound
		}
		return "", err
	}
	const max = 64 << 10
	if len(output) > max {
		output = output[len(output)-max:]
	}
	return string(output), nil
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

// OwnedEnvironment is one container carrying this host's verification labels.
type OwnedEnvironment struct {
	ID        string `json:"environment_id"`
	PlanID    string `json:"plan_id"`
	ProjectID string `json:"project_id"`
	Source    string `json:"source_digest"`
	Request   string `json:"request_digest"`
	ExpiresAt string `json:"expires_at"`
	State     string `json:"state"`
}

// ListOwned finds containers by the verification label. Reclaiming only acts on
// the labels written here, so it cannot delete another project's or another
// host's container by name.
func (p Provider) ListOwned(ctx context.Context, owner string) ([]OwnedEnvironment, error) {
	args := []string{"ps", "-a", "--filter", "label=codexploit.verification=1"}
	if strings.TrimSpace(owner) != "" {
		args = append(args, "--filter", "label=codexploit.owner="+owner)
	}
	args = append(args, "--format", "{{.ID}}")
	output, err := exec.CommandContext(ctx, p.binary(), args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w: %s", err, strings.TrimSpace(string(output)))
	}
	environments := []OwnedEnvironment{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		inspected, err := p.inspect(ctx, id)
		if err != nil {
			continue
		}
		environments = append(environments, OwnedEnvironment{
			ID: id, PlanID: inspected.Config.Labels["codexploit.plan"],
			ProjectID: inspected.Config.Labels["codexploit.project"],
			Source:    inspected.Config.Labels["codexploit.source"],
			Request:   inspected.Config.Labels["codexploit.request"],
			ExpiresAt: inspected.Config.Labels["codexploit.expires_at"],
			State:     inspected.State.Status,
		})
	}
	return environments, nil
}

// Reconcile destroys expired containers this host owns. It is idempotent and only
// reports the identifiers it actually removed.
func (p Provider) Reconcile(ctx context.Context) ([]string, error) {
	owned, err := p.ListOwned(ctx, "")
	if err != nil {
		return nil, err
	}
	now := p.now()
	removed := []string{}
	for _, environment := range owned {
		expires, err := time.Parse(time.RFC3339, environment.ExpiresAt)
		if err != nil || expires.After(now) {
			continue
		}
		if err := p.Destroy(ctx, verify.EnvironmentHandle{ID: environment.ID}); err == nil {
			removed = append(removed, environment.ID)
		}
	}
	return removed, nil
}

type inspectedContainer struct {
	ID       string `json:"Id"`
	Image    string `json:"Image"`
	Platform string `json:"Platform"`
	State    struct {
		Status string `json:"Status"`
	} `json:"State"`
	Config struct {
		User   string            `json:"User"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
		NetworkMode    string            `json:"NetworkMode"`
		Memory         int64             `json:"Memory"`
		NanoCpus       int64             `json:"NanoCpus"`
		PidsLimit      *int64            `json:"PidsLimit"`
		CapDrop        []string          `json:"CapDrop"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		Tmpfs          map[string]string `json:"Tmpfs"`
	} `json:"HostConfig"`
	Mounts []mountInfo `json:"Mounts"`
}

type mountInfo struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

func (p Provider) inspect(ctx context.Context, id string) (inspectedContainer, error) {
	command := exec.CommandContext(ctx, p.binary(), "inspect", "--format", "{{json .}}", id)
	output, err := command.CombinedOutput()
	if err != nil {
		return inspectedContainer{}, fmt.Errorf("docker inspect: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var inspected inspectedContainer
	if err := json.Unmarshal(output, &inspected); err != nil {
		return inspectedContainer{}, fmt.Errorf("docker inspect: %w", err)
	}
	return inspected, nil
}

func (p Provider) findByIdentity(ctx context.Context, requestDigest string, spec runSpec) (verify.EnvironmentHandle, bool, error) {
	command := exec.CommandContext(ctx, p.binary(), "ps", "-a", "--filter", "label=codexploit.request="+requestDigest, "--format", "{{.ID}}")
	output, err := command.CombinedOutput()
	if err != nil {
		return verify.EnvironmentHandle{}, false, fmt.Errorf("docker ps: %w: %s", err, strings.TrimSpace(string(output)))
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return verify.EnvironmentHandle{}, false, nil
	}
	id := strings.TrimSpace(lines[0])
	inspected, err := p.inspect(ctx, id)
	if err != nil {
		return verify.EnvironmentHandle{}, false, err
	}
	if inspected.State.Status != "running" && inspected.State.Status != "created" {
		return verify.EnvironmentHandle{}, false, nil
	}
	handle, err := p.verifyApplied(ctx, id, spec)
	if err != nil {
		return verify.EnvironmentHandle{}, false, err
	}
	return handle, true, nil
}

func (p Provider) imagePlatform(ctx context.Context, image string) (string, string) {
	if strings.TrimSpace(image) == "" {
		return "", ""
	}
	command := exec.CommandContext(ctx, p.binary(), "image", "inspect", "--format", "{{.Os}} {{.Architecture}}", image)
	output, err := command.Output()
	if err != nil {
		return "", ""
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) != 2 {
		return "", ""
	}
	return fields[0], fields[1]
}

func (p Provider) version(ctx context.Context) string {
	command := exec.CommandContext(ctx, p.binary(), "version", "--format", "{{.Server.Version}}")
	if output, err := command.Output(); err == nil {
		return strings.TrimSpace(string(output))
	}
	return ""
}

type runSpec struct {
	Name          string
	Policy        verify.ContainerPolicy
	SourcePath    string
	SourceDigest  string
	RequestDigest string
	PlanID        string
	ProjectID     string
	Owner         string
	Command       []string
	ExpiresAt     time.Time
}

// runArgs is the whole isolation contract in one place, so it can be asserted
// without a daemon.
func runArgs(spec runSpec) []string {
	args := []string{
		"run", "-d",
		"--name", spec.Name,
		"--user", spec.Policy.User,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--network", "none",
		"--memory", fmt.Sprintf("%dm", spec.Policy.MemoryMB),
		"--memory-swap", fmt.Sprintf("%dm", spec.Policy.MemoryMB),
		"--cpus", fmt.Sprintf("%.2f", float64(spec.Policy.CPUMillis)/1000),
		"--pids-limit", strconv.Itoa(spec.Policy.PIDs),
		"--ulimit", "nofile=256:256",
		"--tmpfs", fmt.Sprintf("/tmp:rw,noexec,nosuid,nodev,size=%dm", spec.Policy.ScratchMB),
		"--tmpfs", fmt.Sprintf("/scratch:rw,nosuid,nodev,size=%dm", spec.Policy.ScratchMB),
		"--mount", fmt.Sprintf("type=bind,source=%s,target=/source,readonly", spec.SourcePath),
		"--workdir", "/source",
		"--label", "codexploit.verification=1",
		"--label", "codexploit.plan=" + spec.PlanID,
		"--label", "codexploit.project=" + spec.ProjectID,
		"--label", "codexploit.owner=" + spec.Owner,
		"--label", "codexploit.source=" + spec.SourceDigest,
		"--label", "codexploit.request=" + spec.RequestDigest,
		"--label", "codexploit.expires_at=" + spec.ExpiresAt.UTC().Format(time.RFC3339),
	}
	for _, entry := range spec.Policy.Env {
		args = append(args, "--env", entry)
	}
	command := append([]string(nil), spec.Command...)
	if len(command) == 0 {
		command = []string{"sleep", strconv.Itoa(max(spec.Policy.TTLSeconds, 1))}
	}
	args = append(args, "--entrypoint", command[0], spec.Policy.Image)
	return append(args, command[1:]...)
}

func serviceCommand(env verify.PlanEnvironment) []string {
	if len(env.Services) == 0 {
		return nil
	}
	return append([]string(nil), env.Services[0].Command...)
}

func environmentRequestDigest(request verify.EnvironmentRequest) string {
	h := sha256.New()
	for _, field := range []string{
		request.Plan.ID, request.Plan.DigestOf(), request.Approval.Digest,
		request.Source.SnapshotID, request.Source.Digest,
	} {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

func receiptDigest(receipt verify.EnvironmentReceipt, request string) string {
	h := sha256.New()
	for _, field := range []string{
		request, receipt.EnvironmentID, receipt.ImageDigest, receipt.NetworkMode,
		fmt.Sprint(receipt.SourceReadOnly), receipt.SourceDigest, fmt.Sprint(receipt.CPUMillis),
		fmt.Sprint(receipt.MemoryMB), fmt.Sprint(receipt.MaxProcesses),
		fmt.Sprint(receipt.ScratchMB), fmt.Sprint(receipt.TTLSeconds),
		strings.Join(receipt.Applied, ","),
	} {
		fmt.Fprintf(h, "%d:%s", len(field), field)
	}
	return "receipt-" + hex.EncodeToString(h.Sum(nil)[:12])
}

func expired(handle verify.EnvironmentHandle, now time.Time) bool {
	if strings.TrimSpace(handle.ExpiresAt) == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, handle.ExpiresAt)
	return err == nil && !expires.After(now)
}

func findMount(mounts []mountInfo, destination string) (mountInfo, bool) {
	for _, mount := range mounts {
		if mount.Destination == destination {
			return mount, true
		}
	}
	return mountInfo{}, false
}

func hasSocketMount(mounts []mountInfo) bool {
	for _, mount := range mounts {
		if strings.Contains(mount.Source, "docker.sock") || strings.Contains(mount.Destination, "docker.sock") {
			return true
		}
	}
	return false
}

func hasCapDropAll(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(value, "ALL") {
			return true
		}
	}
	return false
}

func hasNoNewPrivileges(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(value, "no-new-privileges") || strings.EqualFold(value, "no-new-privileges:true") {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// cappedBuffer keeps a bounded prefix of a command's output and counts what it
// dropped, so an observation can say it was truncated instead of pretending to be
// the whole output.
type cappedBuffer struct {
	limit     int64
	written   int64
	truncated bool
	discarded int64
	buf       []byte
}

func newCappedBuffer(limit int64) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.written >= b.limit {
		b.truncated = true
		b.discarded += int64(len(p))
		return len(p), nil
	}
	room := b.limit - b.written
	if int64(len(p)) > room {
		b.truncated = true
		b.discarded += int64(len(p)) - room
		p = p[:room]
	}
	b.buf = append(b.buf, p...)
	b.written += int64(len(p))
	return len(p), nil
}

func (b *cappedBuffer) String() string { return string(b.buf) }
