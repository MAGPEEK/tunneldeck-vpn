import { describe, expect, it } from 'vitest';
import type { FirewallRule } from '../../api/firewall';
import {
  draftsDiffer,
  errorsByDraft,
  formatPort,
  invalidPortFields,
  isPortForward,
  moveDraft,
  newDraft,
  parsePort,
  toDraft,
  toRule,
  visiblePortFields,
} from './ruleDraft';

/** The host's own LAN addresses. */
const HOST = ['192.168.1.10'];

const forward: FirewallRule = {
  id: 'f',
  name: 'Web',
  direction: 'inbound',
  action: 'accept',
  protocol: 'tcp',
  source: '',
  destination: '192.168.1.2',
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
    expect(toRule(toDraft(forward), HOST)).toEqual(forward);
  });

  it('drops fields that do not apply to the protocol and destination', () => {
    const draft = { ...toDraft(forward), protocol: 'esp' as const, icmpType: 'echo-request' };
    expect(toRule(draft, HOST)).toEqual({
      ...forward,
      protocol: 'esp',
      destinationPort: undefined,
      publicPort: undefined,
    });
    const toHost = {
      ...toDraft(forward),
      destination: ' 192.168.1.10 ',
      action: 'drop' as const,
    };
    const rule = toRule(toHost, HOST);
    expect(rule.destination).toBe('192.168.1.10');
    expect(rule.publicPort).toBeUndefined();
    expect(rule.keepSourceAddress).toBe(false);
    expect(rule.action).toBe('drop');
  });

  it('sends an empty port as any port, without a public port for a forward', () => {
    const anyPort = { ...toDraft(forward), destinationPort: '', sourcePort: '' };
    expect(toRule(anyPort, HOST)).toEqual({
      ...forward,
      destinationPort: undefined,
      publicPort: undefined,
    });
  });

  it('forces accept for port forwards and keeps the ICMP type only for ICMP', () => {
    expect(toRule({ ...toDraft(forward), action: 'reject' }, HOST).action).toBe('accept');
    const ping = { ...newDraft('inbound'), protocol: 'icmp' as const, icmpType: 'echo-request' };
    expect(toRule(ping, HOST).icmpType).toBe('echo-request');
  });

  it('treats a rule to any of the host addresses as a rule to the host', () => {
    const toSecond = { ...toDraft(forward), destination: '10.10.0.1', action: 'drop' as const };
    expect(toRule(toSecond, HOST).action).toBe('accept');
    expect(toRule(toSecond, [...HOST, '10.10.0.1']).action).toBe('drop');
  });
});

describe('isPortForward', () => {
  it('is false while the destination is empty, so the action stays editable', () => {
    expect(isPortForward(newDraft('inbound'), HOST)).toBe(false);
    expect(isPortForward({ ...newDraft('inbound'), destination: '192.168.1.2' }, HOST)).toBe(true);
    expect(isPortForward({ ...newDraft('inbound'), destination: '192.168.1.10' }, HOST)).toBe(
      false,
    );
    expect(isPortForward({ ...newDraft('outbound'), destination: '10.0.0.0/8' }, HOST)).toBe(false);
  });

  it('keeps the chosen action of a new rule without destination', () => {
    expect(toRule({ ...newDraft('inbound'), action: 'reject' }, HOST).action).toBe('reject');
  });
});

describe('outbound destination', () => {
  it('sends an empty destination as everything behind the VPN', () => {
    const draft = { ...newDraft('outbound'), source: '192.168.1.20' };
    expect(toRule(draft, HOST).destination).toBe('0.0.0.0/0');
    expect(toRule({ ...draft, destination: '10.0.0.0/8' }, HOST).destination).toBe('10.0.0.0/8');
  });
});

describe('newDraft', () => {
  it('defaults inbound rules to TCP+UDP and outbound rules to any protocol, without a destination', () => {
    expect(newDraft('inbound')).toMatchObject({ protocol: 'tcp+udp', destination: '' });
    expect(newDraft('outbound')).toMatchObject({ protocol: 'any', destination: '' });
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
  const a = newDraft('inbound');
  const out = newDraft('outbound');
  const b = newDraft('inbound');
  const list = [a, out, b];

  it('moves by one place in the whole list and stops at the ends', () => {
    expect(moveDraft(list, b.key, -1)).toEqual([a, b, out]);
    expect(moveDraft(list, a.key, -1)).toEqual(list);
    expect(moveDraft(list, b.key, 1)).toEqual(list);
  });

  it('swaps with the next shown draft when the list is filtered', () => {
    const inbound = (draft: { direction: string }) => draft.direction === 'inbound';
    expect(moveDraft(list, b.key, -1, inbound)).toEqual([b, out, a]);
    expect(moveDraft(list, a.key, 1, inbound)).toEqual([b, out, a]);
  });
});

describe('draftsDiffer', () => {
  it('ignores the highlight and compares what would be sent', () => {
    const draft = toDraft(forward, true);
    expect(draftsDiffer([draft], [forward], HOST)).toBe(false);
    expect(draftsDiffer([{ ...draft, destinationPort: '444' }], [forward], HOST)).toBe(true);
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
