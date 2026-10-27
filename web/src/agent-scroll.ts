export const FOLLOW_LATEST_THRESHOLD = 80;

export interface ScrollMetrics {
  scrollHeight: number;
  scrollTop: number;
  clientHeight: number;
}

export function isFollowingLatest(
  metrics: ScrollMetrics,
  threshold = FOLLOW_LATEST_THRESHOLD,
) {
  if (metrics.scrollHeight <= metrics.clientHeight) return true;
  return metrics.scrollHeight - metrics.scrollTop - metrics.clientHeight <= threshold;
}
