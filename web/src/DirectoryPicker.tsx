import { useEffect, useRef, useState } from "react";
import { FolderOpen } from "lucide-react";
import { prepareDirectory } from "./directory-import";
import type { DirectorySelection } from "./directory-import";
import { FilePicker } from "./FilePicker";

export function DirectoryPicker({ onChange }: { onChange: (selection?: DirectorySelection) => void }) {
  const [selection, setSelection] = useState<DirectorySelection>();
  const [error, setError] = useState("");
  const [reading, setReading] = useState(false);
  const [name, setName] = useState("");
  const controller = useRef<AbortController>();
  useEffect(() => () => controller.current?.abort(), []);
  const supported = "webkitdirectory" in document.createElement("input");
  return <>
    <FilePicker
      label="选择电脑上的源码目录"
      action="选择目录"
      icon={<FolderOpen size={15} />}
      directory
      multiple
      disabled={!supported || reading}
      value={name}
      onChange={async event => {
        controller.current?.abort();
        const current = new AbortController(); controller.current = current;
        const files = event.currentTarget.files;
        setName(Array.from(files || [])[0]?.webkitRelativePath.split("/")[0] || "");
        onChange(undefined); setSelection(undefined); setError(""); setReading(true);
        try {
          const next = await prepareDirectory(Array.from(files || []), current.signal);
          if (!current.signal.aborted) { setSelection(next); onChange(next); }
        } catch (caught) {
          if (!current.signal.aborted) {
            setError(caught instanceof Error ? caught.message : "目录读取失败，请重新选择。");
            setName("");
          }
        } finally { if (!current.signal.aborted) setReading(false); }
      }}
      hint="仅上传筛选后的相对路径和文件内容；≤ 128 MiB、10000 个源码文件，单文件 ≤ 4 MiB。生成目录、版本库与明确敏感文件在读取内容前排除。本次上传固定所读取的字节；读取期间请勿修改文件。"
    />
    {!supported && <p role="alert" className="error-message">当前浏览器不支持目录选择，请使用上传压缩包入口。</p>}
    {reading && <p role="status" className="file-picker-status"><progress /> 正在筛选文件并核对摘要…</p>}
    {selection && <div className="file-picker-result" role="status">
      <div className="file-picker-summary">
        <span>将上传 <strong>{selection.files.length}</strong> 个文件</span>
        <span>{(selection.bytes / 1024).toFixed(1)} KiB</span>
        {selection.summary.excludedFiles > 0 && <span>排除 <strong>{selection.summary.excludedFiles}</strong> 个文件
          {selection.summary.excludedDirectoryCount > 0 && `（${selection.summary.excludedDirectoryCount} 个目录按整目录合并）`}</span>}
      </div>
      {(selection.summary.directories.length > 0 || selection.summary.files.length > 0) && <details className="file-picker-excluded">
        <summary>查看排除项</summary>
        <ul>
          {selection.summary.directories.map(directory => <li key={directory.path}><code>{directory.path}</code> · {directory.files} 个文件</li>)}
          {selection.summary.files.map(path => <li key={path}><code>{path}</code></li>)}
        </ul>
        {selection.summary.omitted > 0 && <p>另有 {selection.summary.omitted} 项未列出；排除记录最多保留 200 项。</p>}
      </details>}
    </div>}
    {error && <p className="error-message" role="alert">{error}</p>}
  </>;
}
