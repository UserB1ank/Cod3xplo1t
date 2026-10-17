import { useEffect, useState, type FormEvent } from "react";
import {
  Check,
  KeyRound,
  Loader2,
  PlugZap,
  Save,
  Settings2,
} from "lucide-react";
import { ApiClient } from "./api";
import { Hint, Panel } from "./components";
import type { Identity } from "./workbench";

interface Settings {
  enabled: boolean;
  protocol: string;
  base_url: string;
  model: string;
  api_key_configured: boolean;
  timeout_seconds: number;
  max_output_tokens: number;
  version: string;
}

export function LLMSettings({
  api,
  identity,
  onSaved,
}: {
  api: ApiClient;
  identity: Identity;
  onSaved: () => Promise<void>;
}) {
  const [settings, setSettings] = useState<Settings>();
  const [key, setKey] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    if (identity.role !== "admin" || !identity.features.llm_settings) return;
    const controller = new AbortController();
    api
      .get<Settings>("/settings/llm", controller.signal)
      .then((value) => {
        setSettings(value);
        setKey("");
        setClearKey(false);
      })
      .catch((error) => {
        if (!controller.signal.aborted) setError(error.message);
      });
    return () => controller.abort();
  }, [api, identity.role, identity.features.llm_settings, reload]);
  if (identity.role !== "admin")
    return <Hint>只有管理员可以查看和修改模型配置。</Hint>;
  if (!identity.features.llm_settings)
    return (
      <Hint>当前服务未启用程序内模型设置，请使用 Docker 默认配置启动。</Hint>
    );
  const update = <K extends keyof Settings>(name: K, value: Settings[K]) => {
    setSettings((current) => current && { ...current, [name]: value });
    setNotice("");
  };
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!settings || busy) return;
    const testing =
      (event.nativeEvent as SubmitEvent).submitter?.getAttribute("value") ===
      "test";
    setBusy(testing ? "test" : "save");
    setError("");
    setNotice("");
    const { version, api_key_configured: _configured, ...draft } = settings;
    const body = {
      ...draft,
      clear_api_key: clearKey,
      ...(key && !clearKey ? { api_key: key } : {}),
    };
    try {
      if (testing) {
        const result = await api.post<{ message: string }>(
          "/settings/llm/test",
          body,
          undefined,
          { "If-Match": `"${version}"` },
        );
        setNotice(result.message);
      } else {
        const response = await api.response("/settings/llm", {
          method: "PUT",
          headers: { "If-Match": `"${version}"` },
          body: JSON.stringify(body),
        });
        setSettings((await response.json()) as Settings);
        setKey("");
        setClearKey(false);
        setNotice(
          "模型配置已保存。新任务使用新配置，正在运行的任务继续使用原配置。",
        );
        await onSaved();
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : "操作失败");
    } finally {
      setBusy("");
    }
  };
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">MODEL CONNECTION</div>
          <h1>模型设置</h1>
          <p>为所有项目配置挖掘模型，保存后立即生效。</p>
        </div>
        <span
          className={`status-pill ${identity.features.agent ? "healthy" : ""}`}
        >
          <span
            className={`connection-dot ${identity.features.agent ? "connected" : ""}`}
          />
          {identity.features.agent ? "模型已启用" : "等待配置"}
        </span>
      </div>
      {error && (
        <div className="error-message" role="alert">
          {error}
          <button
            className="text-button"
            disabled={!!busy}
            onClick={() => {
              setError("");
              setNotice("");
              setReload((n) => n + 1);
            }}
          >
            重新读取配置
          </button>
        </div>
      )}
      {notice && (
        <div className="success-message" role="status">
          <Check size={16} />
          {notice}
        </div>
      )}
      {!settings ? (
        <div className="loading">
          <Loader2 className="spin" size={20} />
          正在读取模型配置…
        </div>
      ) : (
        <div className="model-settings-layout">
          <Panel title="LLM 连接配置" eyebrow="SERVER-SIDE CONFIGURATION">
            <form
              className="model-settings-form"
              onSubmit={submit}
              autoComplete="off"
            >
              <fieldset disabled={!!busy}>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={settings.enabled}
                    onChange={(e) => update("enabled", e.target.checked)}
                  />
                  启用 LLM 漏洞挖掘
                </label>
                <label>
                  接口协议
                  <select
                    value={settings.protocol}
                    onChange={(e) => update("protocol", e.target.value)}
                  >
                    <option value="chat-completions">
                      OpenAI 兼容 · Chat Completions
                    </option>
                    <option value="responses">OpenAI · Responses API</option>
                  </select>
                </label>
                <label>
                  Base URL
                  <input
                    required
                    type="url"
                    maxLength={2048}
                    value={settings.base_url}
                    onChange={(e) => update("base_url", e.target.value)}
                    placeholder="https://api.openai.com/v1"
                    spellCheck={false}
                  />
                </label>
                <small>
                  填写 API 根地址，程序自动追加{" "}
                  {settings.protocol === "responses"
                    ? "/responses"
                    : "/chat/completions"}
                  。本地模型可使用 HTTP 地址。
                </small>
                <label>
                  模型名称
                  <input
                    required
                    maxLength={200}
                    value={settings.model}
                    onChange={(e) => update("model", e.target.value)}
                    placeholder="填写服务商提供的模型 ID"
                    spellCheck={false}
                  />
                </label>
                <label>
                  API Key
                  <span className="secret-state">
                    <KeyRound size={13} />
                    {settings.api_key_configured
                      ? "已加密保存"
                      : "尚未设置 · 本地无鉴权模型可留空"}
                  </span>
                  <input
                    type="password"
                    name="llm-api-key"
                    autoComplete="new-password"
                    maxLength={8192}
                    value={key}
                    disabled={clearKey}
                    onChange={(e) => {
                      setKey(e.target.value);
                      setNotice("");
                    }}
                    placeholder={
                      settings.api_key_configured
                        ? "留空保留原 Key；输入新 Key 可替换"
                        : "输入 API Key"
                    }
                  />
                </label>
                {settings.api_key_configured && (
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={clearKey}
                      onChange={(e) => {
                        setClearKey(e.target.checked);
                        setNotice("");
                      }}
                    />
                    清除已保存的 API Key
                  </label>
                )}
                <div className="form-grid">
                  <label>
                    请求超时（秒）
                    <input
                      required
                      type="number"
                      min={5}
                      max={600}
                      value={settings.timeout_seconds}
                      onChange={(e) =>
                        update("timeout_seconds", Number(e.target.value))
                      }
                    />
                  </label>
                  <label>
                    每次输出上限（tokens）
                    <input
                      required
                      type="number"
                      min={256}
                      max={32768}
                      value={settings.max_output_tokens}
                      onChange={(e) =>
                        update("max_output_tokens", Number(e.target.value))
                      }
                    />
                  </label>
                </div>
                <div className="model-settings-actions">
                  <button type="submit" value="test" className="button">
                    {busy === "test" ? (
                      <Loader2 size={16} className="spin" />
                    ) : (
                      <PlugZap size={16} />
                    )}
                    {busy === "test" ? "正在测试…" : "测试连接"}
                  </button>
                  <button type="submit" value="save" className="button primary">
                    {busy === "save" ? (
                      <Loader2 size={16} className="spin" />
                    ) : (
                      <Save size={16} />
                    )}
                    {busy === "save" ? "正在保存…" : "保存配置"}
                  </button>
                </div>
              </fieldset>
            </form>
          </Panel>
          <div className="model-settings-aside">
            <Panel title="配置说明" eyebrow="HOW IT WORKS">
              <div className="settings-explanation">
                <Settings2 size={22} />
                <h3>一次配置，项目共用。</h3>
                <p>
                  选择支持工具调用的模型。OpenAI 的新模型可选
                  Responses；兼容服务选择 Chat Completions。
                </p>
                <p>
                  连接测试会发送一条无源码的工具调用请求，可能产生少量模型费用。测试通过后仍需点击保存。
                </p>
                <p>
                  模型启用后，常驻调度器会处理待运行任务；取消启用可停止领取新任务。正在运行的请求会继续完成。
                </p>
              </div>
            </Panel>
            <Panel title="凭据存储">
              <div className="settings-explanation">
                <p>
                  API Key 经服务端加密写入 Docker
                  数据卷，页面只返回“是否已设置”。不会写入浏览器持久存储或
                  Compose 文件。
                </p>
                <p>
                  更换 Base URL 时需重新输入 Key，或勾选清除
                  Key。请备份整个数据卷以保留配置与解密密钥。
                </p>
                <p>
                  Docker Desktop 访问宿主机模型时，可将地址中的 localhost 换为
                  host.docker.internal。
                </p>
              </div>
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}
