import { describe, expect, it } from 'vitest';
import { i18n } from '../i18n';
import { formatUptime, uptimeParts } from './uptime';

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;
const MONTH = 30 * DAY;

describe('uptimeParts', () => {
  it.each([
    [0, []],
    [59, []],
    [-5, []],
    [MINUTE, [{ unit: 'minutes', count: 1 }]],
    [
      3 * HOUR + 7 * MINUTE + 59,
      [
        { unit: 'hours', count: 3 },
        { unit: 'minutes', count: 7 },
      ],
    ],
    [HOUR, [{ unit: 'hours', count: 1 }]],
    [
      5 * DAY + 4 * HOUR + 12 * MINUTE,
      [
        { unit: 'days', count: 5 },
        { unit: 'hours', count: 4 },
        { unit: 'minutes', count: 12 },
      ],
    ],
    [
      WEEK - 1,
      [
        { unit: 'days', count: 6 },
        { unit: 'hours', count: 23 },
        { unit: 'minutes', count: 59 },
      ],
    ],
    [WEEK, [{ unit: 'weeks', count: 1 }]],
    [
      WEEK + 2 * HOUR + 5 * MINUTE,
      [
        { unit: 'weeks', count: 1 },
        { unit: 'hours', count: 2 },
      ],
    ],
    [MONTH, [{ unit: 'months', count: 1 }]],
    [
      2 * MONTH + WEEK + 3 * DAY + 5 * HOUR,
      [
        { unit: 'months', count: 2 },
        { unit: 'weeks', count: 1 },
        { unit: 'days', count: 3 },
      ],
    ],
    [13 * MONTH, [{ unit: 'months', count: 13 }]],
  ])('splits %d s', (seconds, parts) => {
    expect(uptimeParts(seconds)).toEqual(parts);
  });
});

describe('formatUptime', () => {
  it.each([
    ['en', 30, 'under 1 min'],
    ['de', 30, 'unter 1 min'],
    ['en', 3 * HOUR + 7 * MINUTE, '3 h 7 min'],
    ['en', 5 * DAY + 4 * HOUR + 12 * MINUTE, '5 days 4 h 12 min'],
    ['de', 5 * DAY + 4 * HOUR + 12 * MINUTE, '5 Tage 4 h 12 min'],
    ['en', DAY + HOUR, '1 day 1 h'],
    ['de', DAY + HOUR, '1 Tag 1 h'],
    ['en', 2 * MONTH + WEEK + 3 * DAY, '2 months 1 week 3 days'],
    ['de', 2 * MONTH + WEEK + 3 * DAY, '2 Monate 1 Woche 3 Tage'],
    ['en', MONTH + 2 * WEEK + DAY, '1 month 2 weeks 1 day'],
    ['de', MONTH + 2 * WEEK + DAY, '1 Monat 2 Wochen 1 Tag'],
  ])('formats in %s %d s as "%s"', (language, seconds, text) => {
    expect(formatUptime(i18n.getFixedT(language), seconds)).toBe(text);
  });
});
