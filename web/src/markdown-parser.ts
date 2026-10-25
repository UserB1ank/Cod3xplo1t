export type Inline =
  | { type: "text"; text: string }
  | { type: "code"; text: string }
  | { type: "strong"; children: Inline[] }
  | { type: "em"; children: Inline[] }
  | { type: "link"; href: string; children: Inline[] };

export type Block =
  | { type: "heading"; level: number; children: Inline[] }
  | { type: "paragraph"; children: Inline[] }
  | { type: "quote"; children: Inline[] }
  | { type: "list"; ordered: boolean; items: Inline[][] }
  | { type: "code"; language: string; text: string }
  | { type: "table"; header: Inline[][]; rows: Inline[][][] }
  | { type: "rule" };

const safeHref = (href: string) => {
  const value = href.trim();
  return /^(https?:\/\/|mailto:|#|\/)/i.test(value) ? value : "";
};

/** Inline Markdown is parsed into data, never into raw HTML. */
export function parseInline(source: string): Inline[] {
  const out: Inline[] = [];
  let text = "";
  const flush = () => {
    if (text) out.push({ type: "text", text });
    text = "";
  };
  for (let i = 0; i < source.length; ) {
    const rest = source.slice(i);
    if (rest.startsWith("**") || rest.startsWith("__")) {
      const marker = rest.slice(0, 2);
      const end = source.indexOf(marker, i + 2);
      if (end > i + 2) {
        flush();
        out.push({
          type: "strong",
          children: parseInline(source.slice(i + 2, end)),
        });
        i = end + 2;
        continue;
      }
    }
    if (rest.startsWith("`")) {
      const end = source.indexOf("`", i + 1);
      if (end > i + 1) {
        flush();
        out.push({ type: "code", text: source.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }
    if (rest.startsWith("[") || rest.startsWith("![")) {
      const linkStart = rest.startsWith("![") ? i + 2 : i + 1;
      const labelEnd = source.indexOf("](", linkStart);
      const hrefEnd = labelEnd >= 0 ? source.indexOf(")", labelEnd + 2) : -1;
      if (labelEnd > linkStart && hrefEnd > labelEnd + 2) {
        const href = safeHref(source.slice(labelEnd + 2, hrefEnd));
        if (href) {
          flush();
          out.push({
            type: "link",
            href,
            children: parseInline(source.slice(linkStart, labelEnd)),
          });
          i = hrefEnd + 1;
          continue;
        }
      }
    }
    if (rest.startsWith("*") || rest.startsWith("_")) {
      const marker = rest[0];
      const end = source.indexOf(marker, i + 1);
      const previous = i > 0 ? source[i - 1] : " ";
      const next = source[i + 1] || "";
      const after = end >= 0 ? source[end + 1] || "" : "";
      const validUnderscore =
        marker !== "_" ||
        (!/[A-Za-z0-9]/.test(previous) &&
          !/\s/.test(next) &&
          !/[A-Za-z0-9]/.test(after));
      if (end > i + 1 && source[end + 1] !== marker && validUnderscore) {
        flush();
        out.push({
          type: "em",
          children: parseInline(source.slice(i + 1, end)),
        });
        i = end + 1;
        continue;
      }
    }
    text += source[i];
    i += 1;
  }
  flush();
  return out;
}

function splitTableRow(line: string): string[] {
  const cells: string[] = [];
  let current = "";
  let inCode = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (char === "\\" && line[i + 1] === "|") {
      current += "|";
      i += 1;
      continue;
    }
    if (char === "`") inCode = !inCode;
    if (char === "|" && !inCode) {
      cells.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  cells.push(current.trim());
  if (cells[0] === "") cells.shift();
  if (cells[cells.length - 1] === "") cells.pop();
  return cells;
}

const isDelimiter = (line: string) => {
  const cells = splitTableRow(line);
  return (
    cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/.test(cell.trim()))
  );
};

const isRule = (line: string) => /^\s*([-*_])(?:\s*\1){2,}\s*$/.test(line);
const isFence = (line: string) => /^\s{0,3}(```|~~~)/.test(line);
const heading = (line: string) => line.match(/^\s{0,3}(#{1,6})\s+(.*)$/);
const listItem = (line: string) =>
  line.match(/^\s{0,3}([-*+]|\d+[.)])\s+(.*)$/);

export function parseMarkdown(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  for (let i = 0; i < lines.length; ) {
    const line = lines[i];
    if (!line.trim()) {
      i += 1;
      continue;
    }
    const fence = line.match(/^\s{0,3}(```|~~~)\s*([A-Za-z0-9_+-]*)\s*$/);
    if (fence) {
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith(fence[1])) {
        body.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) i += 1;
      blocks.push({ type: "code", language: fence[2], text: body.join("\n") });
      continue;
    }
    const head = heading(line);
    if (head) {
      blocks.push({
        type: "heading",
        level: head[1].length,
        children: parseInline(head[2].trim()),
      });
      i += 1;
      continue;
    }
    if (isRule(line)) {
      blocks.push({ type: "rule" });
      i += 1;
      continue;
    }
    if (line.trimStart().startsWith(">")) {
      const quote: string[] = [];
      while (i < lines.length && lines[i].trimStart().startsWith(">")) {
        quote.push(lines[i].replace(/^\s*>\s?/, ""));
        i += 1;
      }
      blocks.push({ type: "quote", children: parseInline(quote.join("\n")) });
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && isDelimiter(lines[i + 1])) {
      const header = splitTableRow(line).map(parseInline);
      const rows: Inline[][][] = [];
      i += 2;
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) {
        rows.push(splitTableRow(lines[i]).map(parseInline));
        i += 1;
      }
      blocks.push({ type: "table", header, rows });
      continue;
    }
    const item = listItem(line);
    if (item) {
      const ordered = /^\d/.test(item[1]);
      const items: Inline[][] = [];
      while (i < lines.length) {
        const current = listItem(lines[i]);
        if (current && /^\d/.test(current[1]) === ordered) {
          items.push(parseInline(current[2]));
          i += 1;
          continue;
        }
        if (
          lines[i].trim() &&
          /^\s{2,}\S/.test(lines[i]) &&
          items.length > 0
        ) {
          const last = items[items.length - 1];
          const extra = parseInline(lines[i].trim());
          items[items.length - 1] = [...last, { type: "text", text: " " }, ...extra];
          i += 1;
          continue;
        }
        break;
      }
      blocks.push({ type: "list", ordered, items });
      continue;
    }
    const paragraph: string[] = [line];
    i += 1;
    while (i < lines.length && lines[i].trim()) {
      if (
        isFence(lines[i]) ||
        heading(lines[i]) ||
        isRule(lines[i]) ||
        lines[i].trimStart().startsWith(">") ||
        listItem(lines[i]) ||
        (lines[i].includes("|") &&
          i + 1 < lines.length &&
          isDelimiter(lines[i + 1]))
      )
        break;
      paragraph.push(lines[i]);
      i += 1;
    }
    blocks.push({ type: "paragraph", children: parseInline(paragraph.join("\n")) });
  }
  return blocks;
}
