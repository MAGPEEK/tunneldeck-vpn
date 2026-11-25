import { describe, expect, it } from 'vitest';
import type { LogLine } from '../api/connection';
import { appendLogLines, filterLogLines, formatLogLine } from './logLines';

function line(level: LogLine['level'], text: string): LogLine {
  return { time: '2026-11-25T10:00:00Z', level, text };
}

const lines = [
  line('debug', 'debug detail'),
  line('info', 'Initialization Sequence Completed'),
  line('warn', 'WARNING: cipher none'),
  line('error', 'AUTH_FAILED'),
];

describe('filterLogLines', () => {
  it.each([
    ['all', 4],
    ['warnings', 2],
    ['errors', 1],
  ] as const)('keeps the %s levels', (level, count) => {
    expect(filterLogLines(lines, level, '')).toHaveLength(count);
  });

  it('matches text case-insensitively and combines with the level', () => {
    expect(filterLogLines(lines, 'all', 'cipher').map((l) => l.text)).toEqual([
      'WARNING: cipher none',
    ]);
    expect(filterLogLines(lines, 'all', '  auth_failed ')).toHaveLength(1);
    expect(filterLogLines(lines, 'errors', 'cipher')).toHaveLength(0);
  });
});

describe('appendLogLines', () => {
  it('keeps only the newest lines up to the capacity', () => {
    const many = Array.from({ length: 5 }, (_, i) => line('info', `line ${i}`));
    const result = appendLogLines(many, [line('info', 'line 5')], 3);
    expect(result.map((l) => l.text)).toEqual(['line 3', 'line 4', 'line 5']);
  });

  it('caps at 2000 lines by default', () => {
    const many = Array.from({ length: 2000 }, (_, i) => line('info', `line ${i}`));
    const result = appendLogLines(many, [line('info', 'newest')]);
    expect(result).toHaveLength(2000);
    expect(result[0]?.text).toBe('line 1');
    expect(result.at(-1)?.text).toBe('newest');
  });
});

describe('formatLogLine', () => {
  it('prefixes the local time', () => {
    const date = new Date(2026, 10, 25, 9, 8, 7);
    expect(formatLogLine({ time: date.toISOString(), level: 'info', text: 'hello' })).toBe(
      '09:08:07 hello',
    );
  });
});
