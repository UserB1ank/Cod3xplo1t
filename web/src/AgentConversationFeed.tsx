import {
  forwardRef,
  type ReactNode,
  type UIEventHandler,
} from "react";

export const AgentConversationFeed = forwardRef<
  HTMLDivElement,
  {
    label: string;
    busy?: boolean;
    className: string;
    children: ReactNode;
    onScroll?: UIEventHandler<HTMLDivElement>;
  }
>(function AgentConversationFeed(
  { label, busy = false, className, children, onScroll },
  ref,
) {
  return (
    <div
      ref={ref}
      className={className}
      role="log"
      aria-label={label}
      aria-live="polite"
      aria-relevant="additions"
      aria-busy={busy}
      onScroll={onScroll}
    >
      {children}
    </div>
  );
});
