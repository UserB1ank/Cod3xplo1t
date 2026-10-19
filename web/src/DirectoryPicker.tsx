import { useEffect, useRef, useState } from "react";
import { prepareDirectory } from "./directory-import";
import type { DirectorySelection } from "./directory-import";

export function DirectoryPicker({ onChange }: { onChange: (selection?: DirectorySelection) => void }) {
  const [selection, setSelection] = useState<DirectorySelection>();
  const [error, setError] = useState("");
  const [reading, setReading] = useState(false);
  const controller = useRef<AbortController>();
  useEffect(() => () => controller.current?.abort(), []);
  const supported = "webkitdirectory" in document.createElement("input");
  return <>
    <label>选择电脑上的源码目录
      <input type="file" name="directory" {...{ webkitdirectory: "" }} multiple required disabled={!supported} onChange={async event => {
        controller.current?.abort();
        const current = new AbortController(); controller.current = current;
        onChange(undefined); setSelection(undefined); setError(""); setReading(true);
        try {
          const next = await prepareDirectory(Array.from(event.currentTarget.files || []), current.signal);
          if (!current.signal.aborted) { setSelection(next); onChange(next); }
        } catch (error) {
          if (!current.signal.aborted) setError(error instanceof Error ? error.message : "目录读取失败，请重新选择。");
        } finally { if (!current.signal.aborted) setReading(false); }
      }} />
    </label>
    {!supported && <p role="alert">当前浏览器不支持目录选择，请使用上传压缩包入口。</p>}
    {reading && <p role="status"><progress /> 正在筛选文件并核对摘要…</p>}
    {selection && <div role="status"><p>将上传 {selection.files.length} 个文件 · {(selection.bytes / 1024).toFixed(1)} KiB · 排除 {selection.manifest.excluded.length} 项</p>
      {!!selection.manifest.excluded.length && <details><summary>查看上传前排除项</summary><ul>{selection.manifest.excluded.slice(0, 200).map(path => <li key={path}><code>{path}</code></li>)}</ul>{selection.manifest.excluded.length > 200 && <p>仅列出前 200 项。</p>}</details>}
    </div>}
    {error && <p className="error-message" role="alert">{error}</p>}
    <small>仅上传筛选后的相对路径和文件内容；≤ 128 MiB、10000 个文件，单文件 ≤ 4 MiB。本次上传固定所读取的字节；读取期间请勿修改文件，后续修改需要重新选择并上传。浏览器不提供文件系统原子快照。明确敏感文件与生成目录在发送前排除。</small>
  </>;
}
