import { useState } from "react";
import { FileArchive } from "lucide-react";
import { FilePicker } from "./FilePicker";

export function ArchivePicker({ onChange }: { onChange?: () => void }) {
  const [name, setName] = useState("");
  return <FilePicker
    label="上传源码压缩包"
    action="选择压缩包"
    icon={<FileArchive size={15} />}
    accept=".zip,.tar,.tar.gz,.tgz"
    value={name}
    onChange={event => {
      setName(event.currentTarget.files?.[0]?.name || "");
      onChange?.();
    }}
    hint="ZIP / TAR / TAR.GZ / TGZ · 压缩包 ≤ 64 MiB，展开 ≤ 128 MiB，单文件 ≤ 4 MiB，最多 10000 项。自动过滤版本库、生成目录和明确敏感文件；导入完成后查看排除记录。"
  />;
}
