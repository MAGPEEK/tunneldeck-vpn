import type { TFunction } from 'i18next';

export type UptimeUnit = 'months' | 'weeks' | 'days' | 'hours' | 'minutes';

export interface UptimePart {
  unit: UptimeUnit;
  count: number;
}

const DAY = 86400;

/** Units from largest to smallest with their length in seconds; a month is 30 days. */
const UNITS: readonly (readonly [UptimeUnit, number])[] = [
  ['months', 30 * DAY],
  ['weeks', 7 * DAY],
  ['days', DAY],
  ['hours', 3600],
  ['minutes', 60],
];

/** How many units are shown, counted from the largest non-zero one. */
const SHOWN_UNITS = 3;

/**
 * The largest non-zero unit of a duration and the two units below it,
 * zero ones left out: 2 months 1 week 3 days, 5 days 4 h 12 min, 3 h 7 min.
 * Under a minute gives no parts.
 */
export function uptimeParts(totalSeconds: number): UptimePart[] {
  let rest = Math.max(0, Math.floor(totalSeconds));
  const parts = UNITS.map(([unit, seconds]) => {
    const count = Math.floor(rest / seconds);
    rest -= count * seconds;
    return { unit, count };
  });
  const first = parts.findIndex((part) => part.count > 0);
  if (first < 0) {
    return [];
  }
  return parts.slice(first, first + SHOWN_UNITS).filter((part) => part.count > 0);
}

/** A duration as text in the language of `t`, e.g. "5 days 4 h 12 min". */
export function formatUptime(t: TFunction, totalSeconds: number): string {
  const parts = uptimeParts(totalSeconds);
  if (parts.length === 0) {
    return t('uptime.underMinute');
  }
  return parts.map(({ unit, count }) => t(`uptime.${unit}`, { count })).join(' ');
}
