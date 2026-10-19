package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

func WithLLMSettings(settings *llm.Manager) Option {
	return func(s *Server) { s.LLMSettings = settings }
}

func (s *Server) llmUnavailable(w http.ResponseWriter) bool {
	if s.LLMSettings == nil {
		writeError(w, http.StatusNotImplemented, "llm_settings_unavailable", errors.New("请使用 --agent-runtime llm 启动服务，以启用程序内模型设置"))
		return true
	}
	return false
}

func (s *Server) handleLLMSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.llmUnavailable(w) {
		return
	}
	public, err := s.LLMSettings.Public()
	if err != nil {
		writeLLMError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+public.Version+`"`)
	writeJSON(w, http.StatusOK, public)
}

func (s *Server) handleSaveLLMSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.llmUnavailable(w) {
		return
	}
	version := strings.Trim(r.Header.Get("If-Match"), `"`)
	if version == "" {
		writeError(w, http.StatusPreconditionRequired, "version_required", errors.New("请先读取当前模型配置"))
		return
	}
	var update llm.Update
	if !s.decode(w, r, &update) {
		return
	}
	public, err := s.LLMSettings.Save(update, version)
	if err != nil {
		writeLLMError(w, err)
		return
	}
	w.Header().Set("ETag", `"`+public.Version+`"`)
	writeJSON(w, http.StatusOK, public)
}

func (s *Server) handleTestLLMSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.llmUnavailable(w) {
		return
	}
	version := strings.Trim(r.Header.Get("If-Match"), `"`)
	if version == "" {
		writeError(w, http.StatusPreconditionRequired, "version_required", errors.New("请先读取当前模型配置"))
		return
	}
	var update llm.Update
	if !s.decode(w, r, &update) {
		return
	}
	cfg, err := s.LLMSettings.Candidate(update, version)
	if err != nil {
		writeLLMError(w, err)
		return
	}
	if err := llm.Test(r.Context(), cfg); err != nil {
		writeError(w, http.StatusBadGateway, "llm_test_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "模型连接与工具调用测试通过；尚未保存的修改需要点击保存"})
}

func writeLLMError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, llm.ErrConflict):
		writeError(w, http.StatusPreconditionFailed, "settings_conflict", err)
	case errors.Is(err, llm.ErrKeyUnavailable), errors.Is(err, llm.ErrDecrypt):
		w.Header().Set("Cache-Control", "no-store")
		writeError(w, http.StatusServiceUnavailable, "settings_unavailable", err)
	case errors.Is(err, llm.ErrRepositoryUnavailable):
		w.Header().Set("Cache-Control", "no-store")
		writeError(w, http.StatusServiceUnavailable, "settings_unavailable", errors.New("模型设置暂不可用，请检查共享设置存储连接"))
	default:
		writeError(w, http.StatusBadRequest, "invalid_settings", err)
	}
}
