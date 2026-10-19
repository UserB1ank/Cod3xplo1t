import { ApiClient } from "./api.ts";

export interface DirectorySelection {
  manifest: { files: { path: string; size: number; sha256: string }[]; excluded: string[] };
  files: File[];
  bytes: number;
}

const ignored = new Set(".git .hg .svn .bzr node_modules bower_components vendor third_party thirdparty dist build out target obj bin .venv venv virtualenv __pycache__ .mypy_cache .pytest_cache .tox .eggs .gradle .m2 .terraform .cache .parcel-cache .next .nuxt .svelte-kit .angular .dart_tool .stack-work coverage htmlcov .nyc_output logs tmp .idea .vscode .vs .ds_store __macosx .ssh".split(" "));
function excluded(path: string) {
  return path.toLowerCase().split("/").some(p => ignored.has(p) || p.startsWith(".env") || p.startsWith("._") || /\.(pem|key)$/.test(p) || /^id_(rsa|dsa|ecdsa|ed25519)/.test(p));
}
function validPath(path: string) {
  return path.length <= 2048 && path.split("/").length <= 32 && !/[\\:\x00-\x1f\x7f]/.test(path) && path.split("/").every(p => p && p !== "." && p !== ".." && !/[ .]$/.test(p) && !/^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.|$)/i.test(p));
}

export async function prepareDirectory(input: Iterable<File>, signal?: AbortSignal): Promise<DirectorySelection> {
  const selected = Array.from(input);
  if (!selected.length) throw new Error("未选择目录或目录为空，请重新选择，或上传压缩包。");
  if (selected.length > 10000) throw new Error("目录最多 10000 个文件，请缩小选择范围。");
  const selection: DirectorySelection = { manifest: { files: [], excluded: [] }, files: [], bytes: 0 };
  const seen = new Set<string>();
  let root = "";
  for (const file of selected) {
    signal?.throwIfAborted();
    const parts = file.webkitRelativePath.split("/");
    if (parts.length < 2 || (root && root !== parts[0])) throw new Error("浏览器未提供有效目录路径，请改用压缩包上传。");
    root = parts.shift()!;
    const path = parts.join("/");
    if (!validPath(path) || seen.has(path.toLowerCase())) throw new Error("目录包含无效或重名路径，请调整后重试。");
    seen.add(path.toLowerCase());
    if (excluded(path)) { selection.manifest.excluded.push(path); continue; }
    if (file.size > 4 * 1024 * 1024 || selection.bytes + file.size > 128 * 1024 * 1024) throw new Error("目录最多 128 MiB，单文件最多 4 MiB。");
    const bytes = await file.arrayBuffer(); // one bounded file at a time
    signal?.throwIfAborted();
    if (bytes.byteLength !== file.size) throw new Error("目录文件读取发生变化，请重新选择目录。");
    const sha256 = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), n => n.toString(16).padStart(2, "0")).join("");
    selection.manifest.files.push({ path, size: file.size, sha256 });
    selection.files.push(file);
    selection.bytes += file.size;
  }
  if (!selection.files.length || !selection.bytes) throw new Error("目录为空或文件全部被过滤，请选择包含源码的目录。");
  return selection;
}

export async function importDirectory(api: ApiClient, project: string, source: string, name: string, selection: DirectorySelection, buildKnowledge: boolean, signal?: AbortSignal) {
  const body = new FormData();
  body.append("manifest", JSON.stringify(selection.manifest));
  selection.files.forEach((file, i) => body.append("files", file, selection.manifest.files[i].path));
  const query = new URLSearchParams({ name, format: "directory", build_graph: String(buildKnowledge), build_asg: String(buildKnowledge) });
  return (await api.response(`/v1/projects/${encodeURIComponent(project)}/imports/${encodeURIComponent(source)}?${query}`, { method: "POST", body, signal })).json();
}
