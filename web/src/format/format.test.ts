import { describe, expect, it } from 'vitest';
import {
  durationText,
  formatBitRate,
  formatBytes,
  formatClock,
  formatDateTime,
  parseTime,
} from './format';

describe('formatBytes', () => {
  it.each([
    [0, 'en', '0 B'],
    [999, 'en', '999 B'],
    [1000, 'en', '1.0 kB'],
    [1536, 'en', '1.5 kB'],
    [2_500_000, 'en', '2.5 MB'],
    [3_210_000_000, 'en', '3.2 GB'],
    [2_500_000, 'de', '2,5 MB'],
    [-5, 'en', '0 B'],
  ])('formats %d bytes in %s as %s', (bytes, locale, expected) => {
    expect(formatBytes(bytes, locale)).toBe(expected);
  });
});

describe('formatBitRate', () => {
  it.each([
    [0, 'en', '0 bit/s'],
    [100, 'en', '800 bit/s'],
    [125, 'en', '1.0 kbit/s'],
    [1_500_000, 'en', '12.0 Mbit/s'],
    [1_500_000, 'de', '12,0 Mbit/s'],
  ])('formats %d B/s in %s as %s', (rate, locale, expected) => {
    expect(formatBitRate(rate, locale)).toBe(expected);
  });
});

describe('durationText', () => {
  it.each([
    [0, 'duration.seconds'],
    [59, 'duration.seconds'],
    [61, 'duration.minutesSeconds'],
    [3 * 3600 + 12 * 60 + 5, 'duration.hoursMinutes'],
    [2 * 86400 + 3600, 'duration.daysHours'],
  ])('uses the two largest units for %d s', (seconds, key) => {
    expect(durationText(seconds).key).toBe(key);
  });

  it('splits the seconds into units', () => {
    expect(durationText(90061.9).values).toEqual({ d: 1, h: 1, m: 1, s: 1 });
  });

  it('treats negative durations as zero', () => {
    expect(durationText(-10).values).toEqual({ d: 0, h: 0, m: 0, s: 0 });
  });
});

describe('formatClock', () => {
  it('pads hours, minutes and seconds', () => {
    expect(formatClock(new Date(2026, 0, 1, 4, 5, 6))).toBe('04:05:06');
  });
});

describe('parseTime', () => {
  it('parses RFC 3339 times', () => {
    expect(parseTime('2026-11-25T10:00:00Z')?.toISOString()).toBe('2026-11-25T10:00:00.000Z');
  });

  it.each([undefined, '', 'nope', '0001-01-01T00:00:00Z'])('ignores %s', (value) => {
    expect(parseTime(value)).toBeUndefined();
  });
});

describe('formatDateTime', () => {
  it('shows local date and time in the locale', () => {
    const date = new Date(2026, 10, 25, 11, 5);
    expect(formatDateTime(date, 'en')).toBe('Nov 25, 2026, 11:05 AM');
    expect(formatDateTime(date, 'de')).toBe('25.11.2026, 11:05');
  });
});
