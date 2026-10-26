import { ApiClient } from "./api.ts";

export interface ExcludedDirectory {
  path: string;
  files: number;
}

export interface DirectorySelection {
  manifest: { files: { path: string; size: number; sha256: string }[]; excluded: string[] };
  files: File[];
  bytes: number;
  summary: {
    excludedFiles: number;
    excludedDirectoryCount: number;
    directories: ExcludedDirectory[];
    files: string[];
    omitted: number;
  };
}

const ignored = new Set(".git .hg .svn .bzr node_modules bower_components vendor third_party thirdparty dist build out target obj bin .venv venv virtualenv __pycache__ .mypy_cache .pytest_cache .tox .eggs .gradle .m2 .terraform .cache .parcel-cache .next .nuxt .svelte-kit .angular .dart_tool .stack-work coverage htmlcov .nyc_output logs tmp .idea .vscode .vs .ds_store __macosx .ssh".split(" "));

// excludedPart decides one path component. A generated directory is excluded as a
// whole: listing every file under node_modules or .git is how a hundred-file
// project produced tens of thousands of exclusion records.
function excludedPart(part: string) {
  const lower = part.toLowerCase();
  return ignored.has(lower) || lower.startsWith(".env") || lower.startsWith("._") || /\.(pem|key)$/.test(lower) || /^id_(rsa|dsa|ecdsa|ed25519)/.test(lower);
}

function validPath(path: string) {
  return path.length <= 2048 && path.split("/").length <= 32 && !/[\\:\x00-\x1f\x7f]/.test(path) && path.split("/").every(p => p && p !== "." && p !== ".." && !/[ .]$/.test(p) && !/^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\.|$)/i.test(p));
}

const maxIncludedFiles = 10000;
const maxFileBytes = 4 * 1024 * 1024;
const maxBytes = 8 * 1024 * 1024 * 1024;
// The manifest is a record of what was skipped, not a dump of it: the server keeps
// 200 entries and the response only shows those.
const manifestExcludedLimit = 200;
const listedDirectoryLimit = 100;
const listedFileLimit = 100;

export async function prepareDirectory(input: Iterable<File>, signal?: AbortSignal): Promise<DirectorySelection> {
  const selected = Array.from(input);
  if (!selected.length) throw new Error("未选择目录或目录为空，请重新选择，或上传压缩包。");

  const candidates: { file: File; path: string }[] = [];
  const directories = new Map<string, number>();
  const excludedFiles: string[] = [];
  let excludedFileCount = 0;
  let omitted = 0;
  let root = "";

  for (const file of selected) {
    signal?.throwIfAborted();
    const parts = file.webkitRelativePath.split("/");
    if (parts.length < 2 || (root && root !== parts[0])) throw new Error("浏览器未提供有效目录路径，请改用压缩包上传。");
    root = parts.shift()!;
    const at = parts.findIndex(excludedPart);
    if (at >= 0) {
      excludedFileCount++;
      if (at === parts.length - 1) {
        const entry = parts.join("/");
        if (validPath(entry) && excludedFiles.length < listedFileLimit) excludedFiles.push(entry);
        else omitted++;
      } else {
        const directory = parts.slice(0, at + 1).join("/");
        if (!validPath(directory)) { omitted++; continue; }
        directories.set(directory, (directories.get(directory) ?? 0) + 1);
      }
      continue;
    }
    const path = parts.join("/");
    if (!validPath(path)) throw new Error("目录包含无效路径，请调整后重试。");
    candidates.push({ file, path });
    // The cap is on what will be uploaded, not on what the browser enumerated: a
    // repository with .git and node_modules must not be rejected for its generated
    // directories.
    if (candidates.length > maxIncludedFiles) throw new Error("可选择上传的源码文件超过 10000 个，请缩小选择范围（生成目录已自动排除）。");
  }

  if (!candidates.length) throw new Error("目录为空或文件全部被过滤，请选择包含源码的目录。");

  const listed = Array.from(directories.entries())
    .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0]))
    .slice(0, listedDirectoryLimit)
    .map(([path, files]) => ({ path, files }));
  const listedFilePaths = excludedFiles.slice(0, listedFileLimit).sort();
  const manifestExcluded = [...listed.map(directory => directory.path), ...listedFilePaths].slice(0, manifestExcludedLimit);
  omitted += Math.max(0, directories.size - listed.length) + Math.max(0, excludedFiles.length - listedFilePaths.length);

  const selection: DirectorySelection = {
    manifest: { files: [], excluded: manifestExcluded },
    files: [],
    bytes: 0,
    summary: {
      excludedFiles: excludedFileCount,
      excludedDirectoryCount: directories.size,
      directories: listed,
      files: listedFilePaths,
      omitted,
    },
  };

  const seen = new Set<string>();
  for (const { file, path } of candidates) {
    signal?.throwIfAborted();
    const key = path.toLowerCase();
    if (seen.has(key)) throw new Error("目录包含重名路径（大小写不敏感），请调整后重试。");
    seen.add(key);
    if (file.size > maxFileBytes || selection.bytes + file.size > maxBytes) throw new Error("目录最多 8 GiB，单文件最多 4 MiB。");
    selection.manifest.files.push({ path, size: file.size, sha256: "" });
    selection.files.push(file);
    selection.bytes += file.size;
  }
  return selection;
}

export async function importDirectory(api: ApiClient, project: string, source: string, name: string, selection: DirectorySelection, buildKnowledge: boolean, signal?: AbortSignal) {
  const body = new FormData();
  body.append("manifest", JSON.stringify(selection.manifest));
  selection.files.forEach((file, i) => body.append("files", file, selection.manifest.files[i].path));
  const query = new URLSearchParams({ name, format: "directory", build_graph: String(buildKnowledge), build_asg: String(buildKnowledge) });
  return (await api.response(`/v1/projects/${encodeURIComponent(project)}/imports/${encodeURIComponent(source)}?${query}`, { method: "POST", body, signal })).json();
}
