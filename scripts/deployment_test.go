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

// Remote Git access is an explicit product decision: the default Compose
// deployments enable it, and a deployment that does not want egress sets
// CODEXPLOIT_ALLOW_NETWORK=false. The flag has to be spelled out in every stack,
// otherwise a new stack silently falls back to the binary's conservative default.
func TestComposeDefaultsToPiWithLlmFallback(t *testing.T) {
	for _, file := range []string{"../compose.yaml", "../compose.postgres.yaml"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		body := string(raw)
		if !strings.Contains(body, "--agent-runtime=${CODEXPLOIT_AGENT_RUNTIME:-pi}") {
			t.Errorf("%s does not default to the Pi runtime", file)
		}
		if !strings.Contains(body, "--agent-runtimes=${CODEXPLOIT_AGENT_RUNTIMES:-llm,pi}") {
			t.Errorf("%s does not offer both runtimes", file)
		}
		if !strings.Contains(body, "--pi-worker=/app/pi-worker/dist/main.js") {
			t.Errorf("%s does not point at the worker", file)
		}
	}
}

func TestComposeEnablesRemoteGitByDefault(t *testing.T) {
	for _, file := range []string{"../compose.yaml", "../compose.postgres.yaml"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if !strings.Contains(string(raw), "--allow-network=${CODEXPLOIT_ALLOW_NETWORK:-true}") {
			t.Errorf("%s does not enable remote Git access by default", file)
		}
	}
}

func TestDSFComposeOverlayMountsDotEnvReadOnly(t *testing.T) {
	raw, err := os.ReadFile("../compose.dsf.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "CODEXPLOIT_DSF_ENV_FILE") || !strings.Contains(string(raw), ":/app/.env:ro") {
		t.Fatal("DSF overlay does not mount an external .env read-only")
	}
	ignored, err := os.ReadFile("../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{"**/.env", "**/.env.*"} {
		if !strings.Contains(string(ignored), pattern) {
			t.Fatalf("Docker context does not exclude %s", pattern)
		}
	}
}
