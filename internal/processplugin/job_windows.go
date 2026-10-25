//go:build windows

package processplugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func configureJobProcess(cmd *exec.Cmd) {}
func killJobProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	tool := filepath.Join(os.Getenv("SYSTEMROOT"), "System32", "taskkill.exe")
	_ = exec.Command(tool, "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
	_ = cmd.Process.Kill()
	return nil
}
