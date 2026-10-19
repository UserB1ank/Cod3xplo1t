import { useId } from "react";
import type { ChangeEvent, ReactNode } from "react";

// FilePicker is the shared control for the two upload entries. A native file
// input renders as an operating-system button and ignores the application's
// design; the real input is visually hidden and a normal secondary button opens
// it through its label, so both pickers look like the rest of the forms.
export function FilePicker(props: {
  label: string;
  action: string;
  icon: ReactNode;
  // The form still reads the field by name; a missing name silently uploaded a
  // null file while the picker looked like it had worked.
  name: string;
  accept?: string;
  multiple?: boolean;
  directory?: boolean;
  disabled?: boolean;
  value?: string;
  hint?: ReactNode;
  onChange: (event: ChangeEvent<HTMLInputElement>) => void;
}) {
  const id = useId();
  return (
    <div className="file-picker">
      <span className="file-picker-label" id={`${id}-label`}>{props.label}</span>
      <div className="file-picker-row">
        <label className={`button secondary file-picker-button${props.disabled ? " disabled" : ""}`} htmlFor={id} aria-describedby={`${id}-label`}>
          {props.icon}
          <span>{props.action}</span>
        </label>
        <input
          id={id}
          className="file-picker-input"
          type="file"
          name={props.name}
          accept={props.accept}
          multiple={props.multiple}
          disabled={props.disabled}
          {...(props.directory ? { webkitdirectory: "" } : {})}
          onChange={props.onChange}
        />
        <span className="file-picker-value" title={props.value}>{props.value || "未选择"}</span>
      </div>
      {props.hint && <small className="file-picker-hint">{props.hint}</small>}
    </div>
  );
}
