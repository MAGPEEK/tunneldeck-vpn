import { describe, expect, it } from 'vitest';
import type { FirewallRule } from '../../api/firewall';
import {
  draftsDiffer,
  errorsByDraft,
  formatPort,
  invalidPortFields,
  moveDraft,
  newDraft,
  parsePort,
  toDraft,
  toRule,
  visiblePortFields,
} from './ruleDraft';

const forward: FirewallRule = {
  id: 'f',
  name: 'Web',
  direction: 'inbound',
  action: 'accept',
  protocol: 'tcp',
  source: '',
  destination: { kind: 'address', cidr: '192.168.2.2' },
  destinationPort: { from: 443 },
  publicPort: { from: 4444 },
  keepSourceAddress: true,
  enabled: true,
  comment: '',
};

describe('ports', () => {
  it.each([
    ['', undefined],
    ['443', { from: 443 }],
    [' 8000 - 8010 ', { from: 8000, to: 8010 }],
    ['22-22', { from: 22 }],
    ['http', null],
    ['1-2-3', null],
  ])('parses %j', (text, expected) => {
    expect(parsePort(text)).toEqual(expected);
  });

  it('formats single ports and ranges', () => {
    expect(formatPort(undefined)).toBe('');
    expect(formatPort({ from: 5001 })).toBe('5001');
    expect(formatPort({ from: 8000, to: 8010 })).toBe('8000-8010');
  });
});

describe('toRule', () => {
  it('round-trips a stored rule', () => {
    expect(toRule(toDraft(forward))).toEqual(forward);
  });

  it('drops fields that do not apply to the protocol and destination', () => {
    const draft = { ...toDraft(forward), protocol: 'esp' as const, icmpType: 'echo-request' };
    expect(toRule(draft)).toEqual({
      ...forward,
      protocol: 'esp',
      destinationPort: undefined,
      publicPort: undefined,
    });
    const toHost = {
      ...toDraft(forward),
      destinationKind: 'host' as const,
      action: 'drop' as const,
    };
    const rule = toRule(toHost);
    expect(rule.destination).toEqual({ kind: 'host' });
    expect(rule.publicPort).toBeUndefined();
    expect(rule.keepSourceAddress).toBe(false);
    expect(rule.action).toBe('drop');
  });

  it('forces accept for port forwards and keeps the ICMP type only for ICMP', () => {
    expect(toRule({ ...toDraft(forward), action: 'reject' }).action).toBe('accept');
    const ping = { ...newDraft('inbound'), protocol: 'icmp' as const, icmpType: 'echo-request' };
    expect(toRule(ping).icmpType).toBe('echo-request');
  });
});

describe('newDraft', () => {
  it('defaults inbound rules to TCP+UDP to this device and outbound rules to any protocol', () => {
    expect(newDraft('inbound')).toMatchObject({ protocol: 'tcp+udp', destinationKind: 'host' });
    expect(newDraft('outbound')).toMatchObject({ protocol: 'any', destinationKind: 'address' });
  });
});

describe('visiblePortFields', () => {
  it('shows ports only for TCP and UDP and the public port only inbound', () => {
    expect(visiblePortFields(newDraft('inbound'))).toEqual([
      'sourcePort',
      'destinationPort',
      'publicPort',
    ]);
    expect(visiblePortFields({ ...newDraft('outbound'), protocol: 'udp' })).toEqual([
      'sourcePort',
      'destinationPort',
    ]);
    expect(visiblePortFields({ ...newDraft('inbound'), protocol: 'icmp' })).toEqual([]);
  });

  it('reports port text that cannot be sent', () => {
    expect(invalidPortFields({ ...newDraft('inbound'), destinationPort: 'web' })).toEqual([
      'destinationPort',
    ]);
    expect(invalidPortFields({ ...newDraft('inbound'), protocol: 'esp', sourcePort: 'x' })).toEqual(
      [],
    );
  });
});

describe('moveDraft', () => {
  it('swaps with the neighbour of the same direction and stops at the ends', () => {
    const a = newDraft('inbound');
    const out = newDraft('outbound');
    const b = newDraft('inbound');
    const list = [a, out, b];
    expect(moveDraft(list, b.key, -1)).toEqual([b, out, a]);
    expect(moveDraft(list, a.key, -1)).toEqual(list);
    expect(moveDraft(list, out.key, 1)).toEqual(list);
  });
});

describe('draftsDiffer', () => {
  it('ignores the highlight and compares what would be sent', () => {
    const draft = toDraft(forward, true);
    expect(draftsDiffer([draft], [forward])).toBe(false);
    expect(draftsDiffer([{ ...draft, destinationPort: '444' }], [forward])).toBe(true);
  });
});

describe('errorsByDraft', () => {
  it('maps rules[i].field to the draft that was sent at index i', () => {
    const outbound = newDraft('outbound');
    const sent = [newDraft('inbound'), outbound];
    expect(
      errorsByDraft(
        {
          'rules[1].source': 'is required',
          'rules[1].destination': 'bad',
          'settings.pingLimit': 'x',
          'rules[7].name': 'gone',
        },
        sent,
      ),
    ).toEqual({ [outbound.key]: { source: 'is required', destination: 'bad' } });
  });
});
