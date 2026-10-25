import { useMemo, type ReactNode } from "react";
import { parseMarkdown, type Inline } from "./markdown-parser";

function InlineView({ nodes }: { nodes: Inline[] }): ReactNode {
  return nodes.map((node, index) => {
    if (node.type === "text") return <span key={index}>{node.text}</span>;
    if (node.type === "code") return <code key={index}>{node.text}</code>;
    if (node.type === "strong")
      return (
        <strong key={index}>
          <InlineView nodes={node.children} />
        </strong>
      );
    if (node.type === "em")
      return (
        <em key={index}>
          <InlineView nodes={node.children} />
        </em>
      );
    return (
      <a key={index} href={node.href} target="_blank" rel="noreferrer noopener">
        <InlineView nodes={node.children} />
      </a>
    );
  });
}

/** Safe Markdown renderer: the parser returns React nodes, never raw HTML. */
export function Markdown({ source }: { source: string }) {
  const blocks = useMemo(() => parseMarkdown(source), [source]);
  return (
    <div className="markdown-body">
      {blocks.map((block, index) => {
        if (block.type === "heading") {
          const level = Math.min(6, Math.max(3, block.level + 1));
          const Tag = `h${level}` as "h3" | "h4" | "h5" | "h6";
          return (
            <Tag key={index}>
              <InlineView nodes={block.children} />
            </Tag>
          );
        }
        if (block.type === "rule") return <hr key={index} />;
        if (block.type === "code")
          return (
            <pre key={index} className="markdown-code">
              <code data-language={block.language || undefined}>
                {block.text}
              </code>
            </pre>
          );
        if (block.type === "quote")
          return (
            <blockquote key={index}>
              <InlineView nodes={block.children} />
            </blockquote>
          );
        if (block.type === "list") {
          const Tag = block.ordered ? "ol" : "ul";
          return (
            <Tag key={index}>
              {block.items.map((item, itemIndex) => (
                <li key={itemIndex}>
                  <InlineView nodes={item} />
                </li>
              ))}
            </Tag>
          );
        }
        if (block.type === "table")
          return (
            <div className="markdown-table" key={index}>
              <table>
                <thead>
                  <tr>
                    {block.header.map((cell, cellIndex) => (
                      <th key={cellIndex}>
                        <InlineView nodes={cell} />
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {block.rows.map((row, rowIndex) => (
                    <tr key={rowIndex}>
                      {row.map((cell, cellIndex) => (
                        <td key={cellIndex}>
                          <InlineView nodes={cell} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        return (
          <p key={index}>
            <InlineView nodes={block.children} />
          </p>
        );
      })}
    </div>
  );
}
