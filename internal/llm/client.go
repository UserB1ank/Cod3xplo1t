package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Call struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type Message struct {
	Role       string `json:"role"`
	Content    string `json:"content"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	Calls      []Call `json:"tool_calls,omitempty"`
	// Responses items preserve reasoning state without exposing or persisting it.
	Items []json.RawMessage `json:"-"`
}

type Tool struct {
	Name        string
	Description string
	Parameters  map[string]any
}

type Completion struct {
	Message       Message
	InputTokens   int
	OutputTokens  int
	UsageReported bool
}

// Complete deliberately refuses redirects, limits responses and sanitizes all
// transport/provider errors. Provider error bodies may echo credentials.
func Complete(ctx context.Context, c Config, messages []Message, tools []Tool, forceTool string) (Completion, error) {
	var result Completion
	if _, err := normalize(c); err != nil {
		return result, err
	}
	body := map[string]any{"model": c.Model, "stream": false}
	endpoint := "/chat/completions"
	definitions := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		fn := map[string]any{"name": t.Name, "description": t.Description, "parameters": t.Parameters, "strict": false}
		if c.Protocol == "responses" {
			fn["type"] = "function"
			definitions = append(definitions, fn)
		} else {
			definitions = append(definitions, map[string]any{"type": "function", "function": fn})
		}
	}
	if c.Protocol == "responses" {
		endpoint = "/responses"
		input := make([]any, 0, len(messages))
		for _, m := range messages {
			if len(m.Items) > 0 {
				for _, item := range m.Items {
					input = append(input, item)
				}
				continue
			}
			if m.Role == "tool" {
				input = append(input, map[string]any{"type": "function_call_output", "call_id": m.ToolCallID, "output": m.Content})
			} else {
				input = append(input, map[string]any{"role": m.Role, "content": m.Content})
			}
		}
		body["input"], body["max_output_tokens"], body["store"] = input, c.MaxOutputTokens, false
		body["include"] = []string{"reasoning.encrypted_content"}
		if forceTool != "" {
			body["tool_choice"] = map[string]any{"type": "function", "name": forceTool}
		}
	} else {
		body["messages"], body["max_completion_tokens"] = messages, c.MaxOutputTokens
		if forceTool != "" {
			body["tool_choice"] = map[string]any{"type": "function", "function": map[string]string{"name": forceTool}}
		}
	}
	if len(tools) > 0 {
		body["tools"] = definitions
		body["parallel_tool_calls"] = false
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return result, errors.New("无法编码模型请求")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+endpoint, bytes.NewReader(raw))
	if err != nil {
		return result, errors.New("模型服务地址无效")
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	response, err := client.Do(req)
	if err != nil {
		return result, errors.New("LLM 请求失败，请检查地址、网络或超时设置；不接受重定向")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result, fmt.Errorf("LLM 服务返回 HTTP %d，请检查 API Key、模型和接口协议", response.StatusCode)
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return result, errors.New("模型响应读取失败或超过 2 MiB 上限")
	}
	result.Message.Role = "assistant"
	if c.Protocol == "responses" {
		var doc struct {
			Status string            `json:"status"`
			Output []json.RawMessage `json:"output"`
			Usage  *struct {
				Input  int `json:"input_tokens"`
				Output int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Status != "completed" {
			return result, errors.New("模型 Responses 输出未完成或格式无效，请检查输出上限和模型协议")
		}
		result.Message.Items = doc.Output
		for _, item := range doc.Output {
			var v struct {
				Type      string `json:"type"`
				CallID    string `json:"call_id"`
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
				Content   []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			}
			if json.Unmarshal(item, &v) != nil {
				return result, errors.New("模型 Responses 输出项格式无效")
			}
			if v.Type == "function_call" {
				call := Call{ID: v.CallID, Type: "function"}
				call.Function.Name, call.Function.Arguments = v.Name, v.Arguments
				result.Message.Calls = append(result.Message.Calls, call)
			}
			if v.Type == "message" {
				for _, part := range v.Content {
					if part.Type == "output_text" {
						result.Message.Content += part.Text
					}
				}
			}
		}
		if doc.Usage != nil {
			result.InputTokens, result.OutputTokens, result.UsageReported = doc.Usage.Input, doc.Usage.Output, true
		}
	} else {
		var doc struct {
			Choices []struct {
				Message Message `json:"message"`
				Finish  string  `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				Input  int `json:"prompt_tokens"`
				Output int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(raw, &doc) != nil || len(doc.Choices) != 1 {
			return result, errors.New("模型 Chat Completions 响应格式无效")
		}
		if doc.Choices[0].Finish != "stop" && doc.Choices[0].Finish != "tool_calls" {
			return result, errors.New("模型输出未完成，请检查输出上限或内容限制")
		}
		result.Message = doc.Choices[0].Message
		if doc.Usage != nil {
			result.InputTokens, result.OutputTokens, result.UsageReported = doc.Usage.Input, doc.Usage.Output, true
		}
	}
	if result.InputTokens < 0 || result.OutputTokens < 0 {
		return result, errors.New("模型返回了无效的 token 用量")
	}
	if len(result.Message.Calls) == 0 && strings.TrimSpace(result.Message.Content) == "" {
		return result, errors.New("模型没有返回工具调用或文本")
	}
	return result, nil
}

// Test checks a real model call and function support without sending repository
// content. It never returns the provider's raw response to the browser.
func Test(ctx context.Context, c Config) error {
	if strings.TrimSpace(c.Model) == "" {
		return errors.New("请填写模型名称")
	}
	c.TimeoutSeconds = min(c.TimeoutSeconds, 30)
	c.MaxOutputTokens = min(c.MaxOutputTokens, 1024)
	tool := Tool{Name: "connection_check", Description: "Confirm that the model connection supports function calls.", Parameters: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}}
	result, err := Complete(ctx, c, []Message{{Role: "user", Content: "Call connection_check once. Do not return any other content."}}, []Tool{tool}, tool.Name)
	if err != nil {
		return err
	}
	if len(result.Message.Calls) != 1 || result.Message.Calls[0].Function.Name != tool.Name {
		return errors.New("模型已响应，但未通过工具调用测试，请选择支持 function calling 的模型")
	}
	return nil
}
