package workflowexec

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func bindSettings(t *testing.T) (*llm.Manager, string) {
	t.Helper()
	settings, err := llm.Open(filepath.Join(t.TempDir(), "settings"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := settings.Save(llm.Update{
		Enabled: true, Protocol: "chat-completions", BaseURL: "http://127.0.0.1:1/v1",
		Model: "frozen-model", APIKey: stringPointer("synthetic"), TimeoutSeconds: 5, MaxOutputTokens: 256,
	}, "initial")
	if err != nil {
		t.Fatal(err)
	}
	return settings, public.Version
}

func stringPointer(value string) *string { return &value }

// TestWorkflowBindFreezesAndChecksTheConfigVersion is the recovery boundary: a
// run pins a settings version, and a recovery may not substitute a different one.
func TestWorkflowBindFreezesAndChecksTheConfigVersion(t *testing.T) {
	settings, version := bindSettings(t)
	model := &agent.ModelRuntime{Settings: settings}
	effects := &Effects{Agent: &agent.Runner{Runtime: model}, Runtimes: map[string]agent.Runtime{"llm": model}, DefaultRuntime: "llm"}

	bound, pin, err := effects.Bind(context.Background(), true, workflow.ModelPin{Runtime: "llm"})
	if err != nil {
		t.Fatalf("creation bind: %v", err)
	}
	if bound == nil || pin.Runtime != "llm" || pin.ConfigVersion != version || pin.Model != "frozen-model" {
		t.Fatalf("creation pin = %+v, want the current settings", pin)
	}
	if pin.PromptVersion != agent.PromptVersion {
		t.Errorf("pin prompt version = %q, want %q", pin.PromptVersion, agent.PromptVersion)
	}

	if _, _, err := effects.Bind(context.Background(), true, workflow.ModelPin{Runtime: "llm", ConfigVersion: version}); err != nil {
		t.Fatalf("recovery with the same version: %v", err)
	}
	if _, _, err := effects.Bind(context.Background(), true, workflow.ModelPin{Runtime: "llm", ConfigVersion: "stale"}); !errors.Is(err, workflow.ErrConfigVersionUnavailable) {
		t.Fatalf("recovery with a stale version: %v, want config_version_unavailable", err)
	}
	if _, _, err := effects.Bind(context.Background(), true, workflow.ModelPin{Runtime: "pi"}); !errors.Is(err, workflow.ErrRuntimeUnavailable) {
		t.Fatalf("unknown runtime: %v, want runtime_unavailable", err)
	}
}

func TestWorkflowBindFreezesAPiRuntime(t *testing.T) {
	init, _ := json.Marshal(map[string]any{
		"protocol": "chat-completions", "base_url": "http://127.0.0.1:1/v1",
		"model": "worker-model", "api_key": "synthetic", "timeout_seconds": 5, "max_output_tokens": 256,
	})
	pi, err := agent.NewPiRuntime(agent.PiConfig{
		Name: "pi", Command: []string{"node", "-e", ""}, Init: init,
		PinSource: func() (agent.RuntimePin, error) {
			return agent.RuntimePin{Model: "worker-model", ConfigVersion: "config-1"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	effects := &Effects{Agent: &agent.Runner{Runtime: pi}, Runtimes: map[string]agent.Runtime{"pi": pi}, DefaultRuntime: "pi"}
	bound, pin, err := effects.Bind(context.Background(), true, workflow.ModelPin{Runtime: "pi"})
	if err != nil {
		t.Fatalf("pi bind: %v", err)
	}
	if bound == nil || pin.WorkerVersion != "1.3.0" || pin.ProtocolVersion != "1" || pin.Model != "worker-model" {
		t.Fatalf("pi pin = %+v", pin)
	}
	if _, _, err := effects.Bind(context.Background(), true, workflow.ModelPin{Runtime: "pi", ConfigVersion: "config-1"}); err != nil {
		t.Fatalf("pi recovery with the same config: %v", err)
	}
	if _, _, err := effects.Bind(context.Background(), true, workflow.ModelPin{Runtime: "pi", ConfigVersion: "config-0"}); !errors.Is(err, workflow.ErrConfigVersionUnavailable) {
		t.Fatalf("pi recovery with a stale config: %v", err)
	}
}
