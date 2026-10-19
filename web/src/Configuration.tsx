import { ApiClient } from "./api";
import { LLMSettings } from "./LLMSettings";
import { Storage } from "./Storage";
import type { Identity } from "./workbench";

export function Configuration({ api, identity, section, onSection, onSaved }: {
  api: ApiClient;
  identity: Identity;
  section: "models" | "storage";
  onSection: (section: "models" | "storage") => void;
  onSaved: () => Promise<void>;
}) {
  return <div className="configuration-page">
    <div className="configuration-heading"><h1>配置</h1><p>管理整个工作区的模型连接与数据存储。</p></div>
    <nav className="configuration-tabs" aria-label="配置分类">
      <button className={section === "models" ? "selected" : ""} aria-current={section === "models" ? "page" : undefined} onClick={() => onSection("models")}>模型设置</button>
      <button className={section === "storage" ? "selected" : ""} aria-current={section === "storage" ? "page" : undefined} onClick={() => onSection("storage")}>数据存储</button>
    </nav>
    {section === "storage" ? <Storage api={api} isAdmin={identity.role === "admin"} embedded /> : <LLMSettings api={api} identity={identity} onSaved={onSaved} embedded />}
  </div>;
}
