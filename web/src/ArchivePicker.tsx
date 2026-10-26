import { useRef, useState } from "react";
import { FileArchive } from "lucide-react";
import { FilePicker } from "./FilePicker";

export function ArchivePicker({ onChange }: { onChange?: (file?: File) => void }) {
  const [name, setName] = useState("");
  // The selected File is kept in state instead of being read back from the form:
  // cancelling a second file dialog clears the input's value, and a form-driven
  // upload then submits nothing while the page still shows a name.
  const file = useRef<File>();
  return <FilePicker
    label="上传源码压缩包"
    action="选择压缩包"
    icon={<FileArchive size={15} />}
    name="archive"
    accept=".zip,.tar,.tar.gz,.tgz"
    value={name}
    onChange={event => {
      const selected = event.currentTarget.files?.[0];
      if (!selected) return; // cancelled: keep the previous selection
      file.current = selected;
      setName(selected.name);
      onChange?.(selected);
    }}
    hint="ZIP / TAR / TAR.GZ / TGZ · 压缩包与源码 ≤ 8 GiB；图谱化默认 500 MiB，超过后确认继续，单文件 ≤ 4 MiB，最多 10000 项。自动过滤版本库、生成目录和明确敏感文件；导入完成后查看排除记录。"
  />;
}
