const BYTE_UNITS = ['B', 'kB', 'MB', 'GB', 'TB'] as const;
const BIT_RATE_UNITS = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'] as const;

function scaled(value: number, units: readonly string[], locale: string): string {
  let amount = Math.max(0, value);
  let index = 0;
  while (amount >= 1000 && index < units.length - 1) {
    amount /= 1000;
    index += 1;
  }
  const digits = index === 0 ? 0 : 1;
  const number = new Intl.NumberFormat(locale, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(amount);
  return `${number} ${units[index]}`;
}

/** Bytes in SI units (1 kB = 1000 B) with one decimal: "1.5 MB". */
export function formatBytes(bytes: number, locale: string): string {
  return scaled(bytes, BYTE_UNITS, locale);
}

/** A rate given in bytes per second, shown in bits per second: "12.0 Mbit/s". */
export function formatBitRate(bytesPerSecond: number, locale: string): string {
  return scaled(bytesPerSecond * 8, BIT_RATE_UNITS, locale);
}

export type DurationKey =
  'duration.daysHours' | 'duration.hoursMinutes' | 'duration.minutesSeconds' | 'duration.seconds';

export interface DurationText {
  key: DurationKey;
  values: { d: number; h: number; m: number; s: number };
}

/** The two largest units of a duration, as an i18n key with values: 3 h 12 min. */
export function durationText(totalSeconds: number): DurationText {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const values = {
    d: Math.floor(seconds / 86400),
    h: Math.floor((seconds % 86400) / 3600),
    m: Math.floor((seconds % 3600) / 60),
    s: seconds % 60,
  };
  if (values.d > 0) {
    return { key: 'duration.daysHours', values };
  }
  if (values.h > 0) {
    return { key: 'duration.hoursMinutes', values };
  }
  if (values.m > 0) {
    return { key: 'duration.minutesSeconds', values };
  }
  return { key: 'duration.seconds', values };
}

/** Local wall-clock time HH:MM:SS. */
export function formatClock(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** Parses an RFC 3339 time; Go's zero time and invalid input give undefined. */
export function parseTime(value: string | undefined): Date | undefined {
  if (!value) {
    return undefined;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) || date.getUTCFullYear() < 1971 ? undefined : date;
}

/** Date and time in `timeZone`; an unknown zone name falls back to the browser's zone. */
export function formatZonedTime(iso: string, locale: string, timeZone: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  const options: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'medium' };
  try {
    return new Intl.DateTimeFormat(locale, { ...options, timeZone }).format(date);
  } catch {
    return new Intl.DateTimeFormat(locale, options).format(date);
  }
}
