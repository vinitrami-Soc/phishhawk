/* Dates and sizes, written one way on every screen. The server sends ISO 8601
   timestamps; show them in the viewer's time zone, never as raw ISO text.
   Put the exact value in a tooltip: <time dateTime={iso} title={formatDateTime(iso)}>. */

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** "6 Oct 2026, 17:04". Empty for a missing value; the text itself if it is not a date. */
export function formatDateTime(iso: string | null | undefined, timeZone?: string): string {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return String(iso);
  return new Intl.DateTimeFormat('en-GB', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZone,
  }).format(date);
}

const relative = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

/** "just now", "4 minutes ago", "yesterday", "3 days ago"; the date after a week. */
export function formatRelative(iso: string | null | undefined, now = Date.now(), timeZone?: string): string {
  if (!iso) return '';
  const time = new Date(iso).getTime();
  if (Number.isNaN(time)) return String(iso);
  const seconds = Math.round((now - time) / 1000);
  if (seconds < 0 || seconds >= 7 * DAY) return formatDateTime(iso, timeZone);
  if (seconds < 45) return 'just now';
  if (seconds < HOUR) return relative.format(-Math.max(1, Math.round(seconds / MINUTE)), 'minute');
  if (seconds < DAY) return relative.format(-Math.round(seconds / HOUR), 'hour');
  return relative.format(-Math.round(seconds / DAY), 'day');
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
