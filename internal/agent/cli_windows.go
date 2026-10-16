//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"syscall"
)

// configureProcessGroup starts the child in a new process group.
//
// Windows has no signal an unprivileged parent may send to a group, but the
// creation flag still marks the tree so it can be taken down as a unit.
func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP
}

// killProcessGroup kills the child and its descendants. Go alone cannot walk the
// process tree on Windows, so taskkill /T is the documented way to take the tree
// down; if it is unavailable, the single process is still killed.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if err := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run(); err != nil {
		_ = cmd.Process.Kill()
	}
}
