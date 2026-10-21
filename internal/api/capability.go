package api

import (
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// capabilityAdapter is one concrete way a pipeline stage can run on this host.
// A plugin runtime is not the same thing as the Agent runtime, an environment
// backend or a verification executor; the kind makes that explicit in the
// public catalog.
type capabilityAdapter struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	Version         string   `json:"version,omitempty"`
	ProtocolVersion string   `json:"protocol_version,omitempty"`
	Declared        bool     `json:"declared"`
	Installed       bool     `json:"installed"`
	Measured        bool     `json:"measured"`
	Capabilities    []string `json:"capabilities"`
	Reason          string   `json:"reason,omitempty"`
}

const (
	adapterPluginRuntime        = "plugin_runtime"
	adapterAgentRuntime         = "agent_runtime"
	adapterEnvironmentBackend   = "environment_backend"
	adapterVerificationExecutor = "verification_executor"
	adapterNativeService        = "native_service"
)

func executionModel(capability string) string {
	switch capability {
	case "source":
		return adapterNativeService
	case "agent":
		return adapterAgentRuntime
	case "environment":
		return adapterEnvironmentBackend
	case "verification":
		return adapterVerificationExecutor
	default:
		return plugin.TransportPluginExecute
	}
}

// pluginAdapter projects a catalog record into the common adapter shape. The
// declared/installed/measured triple is the distinction the plugin page needs:
// a manifest can exist without a package, and a package without a host adapter.
func pluginAdapter(record plugin.Record) capabilityAdapter {
	capabilities := []string{}
	for _, language := range record.Manifest.Languages {
		capabilities = append(capabilities, "language:"+language)
	}
	capabilities = append(capabilities, "network:"+record.Manifest.Permissions.Network)
	return capabilityAdapter{
		ID:              record.Manifest.ID + "@" + record.Manifest.Version,
		Name:            record.Manifest.Name,
		Kind:            adapterPluginRuntime,
		Version:         record.Manifest.Version,
		ProtocolVersion: record.ProtocolVersion,
		Declared:        true,
		Installed:       record.Installed,
		Measured:        record.Executable,
		Capabilities:    capabilities,
		Reason:          record.Reason,
	}
}

func (s *Server) nativeAdapters(capability string) []capabilityAdapter {
	switch capability {
	case "source":
		installed := s.Manager != nil
		return []capabilityAdapter{{
			ID: "source/native", Name: "Native source ingestion", Kind: adapterNativeService,
			Version: "1.0.0", ProtocolVersion: "source-input/v1", Declared: true,
			Installed: installed, Measured: installed,
			Capabilities: []string{"archive", "directory", "git", "local_folder"},
			Reason:       sourceAdapterReason(installed),
		}}
	case "agent":
		infos := []agent.RuntimeInfo{}
		if s.AgentRuntimes != nil {
			infos = s.AgentRuntimes()
		}
		if len(infos) == 0 {
			return []capabilityAdapter{{
				ID: "agent/runtime", Name: "Agent runtime", Kind: adapterAgentRuntime,
				Declared: true, Capabilities: []string{},
				Reason: "此部署未配置 Agent runtime；默认纯工具四阶段不受影响。",
			}}
		}
		adapters := make([]capabilityAdapter, 0, len(infos))
		for _, info := range infos {
			capabilities := []string{}
			if info.Capabilities.ToolCalls {
				capabilities = append(capabilities, "tool_calls")
			}
			if info.Capabilities.Expansions {
				capabilities = append(capabilities, "expansions")
			}
			if info.Capabilities.Resume {
				capabilities = append(capabilities, "resume")
			}
			if info.Capabilities.Streaming {
				capabilities = append(capabilities, "streaming")
			}
			if info.Capabilities.TokenUsage {
				capabilities = append(capabilities, "token_usage")
			}
			if info.Capabilities.BatchTools {
				capabilities = append(capabilities, "batch_tools")
			}
			adapters = append(adapters, capabilityAdapter{
				ID: "agent/" + info.Name, Name: info.Name, Kind: adapterAgentRuntime,
				Version: info.Version, ProtocolVersion: info.ProtocolVersion,
				Declared: true, Installed: true, Measured: info.Ready,
				Capabilities: capabilities, Reason: info.Reason,
			})
		}
		return adapters
	case "environment":
		if s.containerVerification == nil || s.containerVerification.Provider == nil {
			return []capabilityAdapter{{
				ID: "environment/backend", Name: "Environment backend", Kind: adapterEnvironmentBackend,
				Declared: true, Capabilities: []string{},
				Reason: "此部署未配置环境供应后端；动态验证保持不可用，静态分析不受影响。",
			}}
		}
		provider := s.containerVerification.Provider
		capabilities := append([]string(nil), provider.Capabilities()...)
		return []capabilityAdapter{{
			ID: "environment/container", Name: "Container environment backend", Kind: adapterEnvironmentBackend,
			Version: "1.0.0", ProtocolVersion: "environment-provider/v1",
			Declared: true, Installed: true, Measured: len(capabilities) > 0,
			Capabilities: capabilities,
		}}
	case "verification":
		if s.Verifier == nil || s.Verifier.Executor == nil {
			return []capabilityAdapter{{
				ID: "verification/executor", Name: "Verification executor", Kind: adapterVerificationExecutor,
				Declared: true, Capabilities: []string{},
				Reason: "此部署未配置验证执行器；动态验证保持不可用，候选不会被提升为已确认。",
			}}
		}
		info := s.Verifier.Executor.Capabilities()
		capabilities := []string{}
		if info.SupportsCommands {
			capabilities = append(capabilities, "commands")
		}
		if info.SupportsStaticQueries {
			capabilities = append(capabilities, "static_queries")
		}
		if info.ReportsExitCode {
			capabilities = append(capabilities, "exit_code")
		}
		reason := strings.Join(info.Notes, "；")
		return []capabilityAdapter{{
			ID: "verification/" + info.Name, Name: info.Name, Kind: adapterVerificationExecutor,
			Version: info.Version, ProtocolVersion: "verification-executor/v1",
			Declared: true, Installed: true, Measured: info.SupportsCommands || info.SupportsStaticQueries,
			Capabilities: capabilities, Reason: reason,
		}}
	default:
		return nil
	}
}

func sourceAdapterReason(installed bool) string {
	if installed {
		return ""
	}
	return "此部署没有可用的源码接入服务"
}

// capabilityReason explains an unavailable stage without claiming a missing
// plugin is the only possible cause.
func capabilityReason(capability string, adapters []capabilityAdapter) string {
	for _, adapter := range adapters {
		if adapter.Measured {
			return ""
		}
	}
	switch capability {
	case "agent":
		return "尚无已就绪的 Agent runtime；可选增强不阻断默认纯工具链。"
	case "environment":
		return "尚无已配置的环境供应后端。"
	case "verification":
		return "尚无已配置的验证执行器。"
	case "source":
		return "源码接入服务不可用。"
	default:
		return "尚无已安装且实测可执行的适配器。"
	}
}
