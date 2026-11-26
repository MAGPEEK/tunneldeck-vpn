import { describe, expect, it } from 'vitest';
import type { ConnectionState } from '../../api/connection';
import { makeFirewall, makeRule, makeStatus } from '../../test/fixtures';
import {
  activeForwards,
  activeRules,
  firewallLine,
  lineLayout,
  protectionsDegraded,
  tunnelLine,
  type LineStyle,
} from './overview';

const forward = makeRule({ id: 'f', destination: '192.168.1.20' });
const outbound = makeRule({ id: 'o', direction: 'outbound', destination: '0.0.0.0/0' });

describe('tunnelLine', () => {
  it.each<[ConnectionState, LineStyle]>([
    ['disconnected', { tone: 'neutral', dashed: true }],
    ['connecting', { tone: 'warning', dashed: false }],
    ['reconnecting', { tone: 'warning', dashed: false }],
    ['disconnecting', { tone: 'warning', dashed: false }],
    ['connected', { tone: 'success', dashed: false }],
    ['error', { tone: 'danger', dashed: false }],
  ])('maps %s', (state, style) => {
    expect(tunnelLine(state)).toEqual(style);
  });
});

describe('firewallLine', () => {
  const idle = makeStatus();

  it.each<[string, Parameters<typeof firewallLine>[0], LineStyle]>([
    ['unknown firewall', undefined, { tone: 'neutral', dashed: true }],
    ['installed firewall', makeFirewall(), { tone: 'success', dashed: false }],
    [
      'global SYN limit only',
      makeFirewall({
        protectionsAvailable: {
          synFlood: 'global',
          ping: 'full',
          mssClamp: 'full',
          ruleCounters: true,
        },
      }),
      { tone: 'warning', dashed: false },
    ],
    [
      'missing protection that is switched off',
      makeFirewall({
        settings: { dropInvalid: true, mssClamp: false, synFloodProtection: true, pingLimit: true },
        protectionsAvailable: {
          synFlood: 'full',
          ping: 'full',
          mssClamp: 'none',
          ruleCounters: true,
        },
      }),
      { tone: 'success', dashed: false },
    ],
    [
      'forwarding off with a forward rule',
      makeFirewall({ rules: [forward], ipForward: false }),
      { tone: 'warning', dashed: false },
    ],
    [
      'forwarding off with an outbound rule',
      makeFirewall({ rules: [outbound], ipForward: false }),
      { tone: 'warning', dashed: false },
    ],
    [
      'forwarding off with host rules only',
      makeFirewall({ ipForward: false }),
      { tone: 'success', dashed: false },
    ],
  ])('shows %s', (_, firewall, style) => {
    expect(firewallLine(firewall, idle)).toEqual(style);
  });

  it('turns red when the firewall could not be applied', () => {
    const failed = makeStatus({
      state: 'error',
      lastError: { code: 'firewall_failed', message: 'x', time: '2026-11-25T10:00:00Z' },
    });
    expect(firewallLine(makeFirewall(), failed)).toEqual({ tone: 'danger', dashed: false });
  });
});

describe('firewall counts', () => {
  it('counts enabled rules and enabled forwards only', () => {
    const firewall = makeFirewall({
      rules: [makeRule(), forward, outbound, { ...forward, id: 'off', enabled: false }],
    });
    expect(activeRules(firewall)).toBe(3);
    expect(activeForwards(firewall)).toBe(1);
    expect(protectionsDegraded(firewall)).toBe(false);
  });
});

describe('lineLayout', () => {
  it.each([
    [true, 'vertical'],
    [false, 'horizontal'],
  ])('narrow %s gives %s', (narrow, layout) => {
    expect(lineLayout(narrow)).toBe(layout);
  });
});
