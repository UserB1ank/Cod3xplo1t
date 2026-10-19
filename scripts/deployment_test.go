package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPostgresStatusUsesUnifiedWebPort(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the deployment wrapper requires a POSIX shell")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ override, want string }{{"", "18085"}, {"18123", "18123"}} {
		t.Run("port_"+tc.want, func(t *testing.T) {
			cmd := exec.Command("bash", "deploy-postgres.sh", "status")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "CODEXPLOIT_PG_PORT=") && !strings.HasPrefix(value, "PATH=") && !strings.HasPrefix(value, "CODEXPLOIT_PG_SECRETS_DIR=") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "CODEXPLOIT_PG_PORT="+tc.override, "CODEXPLOIT_PG_SECRETS_DIR="+t.TempDir())
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("status: %v\n%s", err, output)
			}
			if !strings.Contains(string(output), "URL: http://127.0.0.1:"+tc.want+"\n") {
				t.Fatalf("status did not advertise the selected Web port:\n%s", output)
			}
		})
	}
}
