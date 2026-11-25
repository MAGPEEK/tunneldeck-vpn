import { LOG_CAPACITY, type LogLevel, type LogLine } from '../api/connection';
import { formatClock } from '../format/format';

export type LevelFilter = 'all' | 'warnings' | 'errors';

export const LEVEL_FILTERS: readonly LevelFilter[] = ['all', 'warnings', 'errors'];

const LEVELS_SHOWN: Record<LevelFilter, readonly LogLevel[]> = {
  all: ['debug', 'info', 'warn', 'error'],
  warnings: ['warn', 'error'],
  errors: ['error'],
};

/** Appends lines and keeps only the newest `capacity`. */
export function appendLogLines(
  lines: readonly LogLine[],
  added: readonly LogLine[],
  capacity = LOG_CAPACITY,
): LogLine[] {
  const combined = [...lines, ...added];
  return combined.length > capacity ? combined.slice(combined.length - capacity) : combined;
}

/** The line's local time HH:MM:SS. */
export function logClock(line: LogLine): string {
  const time = new Date(line.time);
  return Number.isNaN(time.getTime()) ? '--:--:--' : formatClock(time);
}

/** A line as copied: local time and text. */
export function formatLogLine(line: LogLine): string {
  return `${logClock(line)} ${line.text}`;
}

/** Lines of the chosen levels whose text contains `text`, ignoring case. */
export function filterLogLines(
  lines: readonly LogLine[],
  level: LevelFilter,
  text: string,
): LogLine[] {
  const levels = LEVELS_SHOWN[level];
  const needle = text.trim().toLowerCase();
  return lines.filter(
    (line) =>
      levels.includes(line.level) && (needle === '' || line.text.toLowerCase().includes(needle)),
  );
}
