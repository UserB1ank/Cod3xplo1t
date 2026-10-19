import { useEffect, useState } from 'react';
import type { ApiClient } from './api';
import type { RuntimeInfo } from './types';
import { Hint, Panel } from './components';

export function RuntimeStatus({ api }: { api: ApiClient }) {
  const [runtimes, setRuntimes] = useState<RuntimeInfo[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    api.get<{ runtimes: RuntimeInfo[] }>('/agent/runtimes', controller.signal)
      .then((value) => setRuntimes(value.runtimes || []))
      .catch((err) => { if (!controller.signal.aborted) setError(String(err)); });
    return () => controller.abort();
  }, [api]);
  return (
    <Panel title="Agent 运行时" action={<span className="subtle-label">部署可用目录</span>}>
      {error && <Hint>{error}</Hint>}
      <div className="table-scroll">
        <table className="standard-table">
          <thead><tr><th>运行时</th><th>状态</th><th>模型</th><th>版本</th><th>说明</th></tr></thead>
          <tbody>
            {runtimes.map((runtime) => (
              <tr key={runtime.name}>
                <td className="mono">{runtime.name}</td>
                <td>{runtime.ready ? '可用' : '不可用'}</td>
                <td>{runtime.model || '—'}</td>
                <td className="mono">
                  {runtime.version || '—'}
                  {runtime.worker_version ? ` · worker ${runtime.worker_version}` : ''}
                </td>
                <td>
                  {runtime.ready
                    ? runtime.config_version
                      ? `配置 ${runtime.config_version.slice(0, 12)}`
                      : '—'
                    : runtime.reason || '未就绪'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!runtimes.length && !error && <Hint>部署没有提供可选择的运行时。</Hint>}
    </Panel>
  );
}
