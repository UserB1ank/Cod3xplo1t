export function ArchivePicker({ onChange }: { onChange?: () => void }) {
  return <>
    <label>上传源码压缩包
      <input type="file" name="archive" accept=".zip,.tar,.tar.gz,.tgz" required onChange={onChange} />
    </label>
    <small>ZIP / TAR / TAR.GZ / TGZ · 压缩包 ≤ 64 MiB，展开 ≤ 128 MiB，单文件 ≤ 4 MiB，最多 10000 项。自动过滤版本库、生成目录和明确敏感文件；导入完成后查看排除记录。</small>
  </>;
}
