export function composerAction(event: {key: string; ctrlKey: boolean; repeat?: boolean; isComposing?: boolean; keyCode?: number}): "send" | "newline" | "ignore" {
  if (event.key !== "Enter" || event.isComposing || event.keyCode === 229 || event.repeat) return "ignore";
  return event.ctrlKey ? "newline" : "send";
}

export function insertComposerNewline(value: string, start: number, end: number) {
  return {value: value.slice(0, start) + "\n" + value.slice(end), cursor: start + 1};
}
