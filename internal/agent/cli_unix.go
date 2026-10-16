//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group.
//
// Without it, cancelling a run reaches only the CLI: a grandchild it spawned keeps
// running, keeps the pipes and can keep spending. A process group is the cheapest
// isolation Go can give an adapter that is not already in a container, and it is
// what makes cancellation mean "this run is over".
func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup signals every process in the child's group. The negative pid
// addresses the group, which is exactly why configureProcessGroup matters.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		// The group may already be gone, or the platform refused it; fall back to
		// the process itself so a run is never left unstoppable.
		_ = cmd.Process.Kill()
	}
}
