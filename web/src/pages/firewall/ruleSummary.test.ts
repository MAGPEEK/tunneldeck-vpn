import { describe, expect, it } from 'vitest';
import { i18n } from '../../i18n';
import { newDraft, type RuleDraft } from './ruleDraft';
import { ruleCreates, ruleSummary } from './ruleSummary';
import { flowEndpoints, ruleLine, suggestedName, type RuleContext } from './ruleText';

const t = i18n.getFixedT('en');

const context: RuleContext = {
  hostAddresses: ['192.168.1.10'],
  devices: [
    {
      address: '192.168.1.20',
      mac: '02:00:00:00:00:20',
      name: 'Web server',
      state: 'REACHABLE',
      onLan: true,
    },
  ],
};

const toHost: RuleDraft = {
  ...newDraft('inbound'),
  name: 'Admin',
  protocol: 'tcp',
  destination: '192.168.1.10',
  destinationPort: '443',
};

const forward: RuleDraft = {
  ...newDraft('inbound'),
  id: 'f',
  name: 'Web',
  protocol: 'tcp',
  source: '203.0.113.0/24',
  destination: '192.168.1.20',
  destinationPort: '443',
  publicPort: '4444',
};

const outbound: RuleDraft = { ...newDraft('outbound'), name: 'Out', source: '192.168.1.20' };

const block: RuleDraft = {
  ...newDraft('inbound'),
  name: 'Block',
  action: 'drop',
  protocol: 'any',
  source: '198.51.100.7',
  destination: '192.168.1.10',
};

describe('ruleSummary', () => {
  it('describes a service opened on this device', () => {
    expect(ruleSummary(t, toHost, context)).toEqual([
      'Connections from any sender to this device (192.168.1.10) on TCP port 443 are allowed.',
    ]);
    const senderPort = { ...toHost, destinationPort: '', sourcePort: '1024-2000' };
    expect(ruleSummary(t, senderPort, context)).toEqual([
      'Connections from any sender (port 1024-2000) to this device (192.168.1.10) on every TCP port are allowed.',
    ]);
  });

  it('describes a port forward and the sender the device sees', () => {
    expect(ruleSummary(t, forward, context)).toEqual([
      'Connections from 203.0.113.0/24 to the VPN address on TCP port 4444 go to Web server (192.168.1.20) on TCP port 443.',
      'Web server sees this device as the sender.',
    ]);
    const keep = { ...forward, keepSourceAddress: true, destination: '192.168.1.30' };
    expect(ruleSummary(t, keep, context)).toEqual([
      'Connections from 203.0.113.0/24 to the VPN address on TCP port 4444 go to 192.168.1.30 on TCP port 443.',
      '192.168.1.30 sees the original sender and must send its replies back through this device.',
    ]);
    const esp = { ...forward, protocol: 'esp' as const, source: '' };
    expect(ruleSummary(t, esp, context)[0]).toBe(
      'Connections from any sender to the VPN address via ESP go to Web server (192.168.1.20) via ESP.',
    );
  });

  it('describes an outbound rule with the kill switch', () => {
    expect(ruleSummary(t, outbound, context)).toEqual([
      'Traffic from Web server (192.168.1.20) to any address behind the VPN goes through the VPN with the VPN address as sender.',
      'While the VPN is down, this traffic is blocked.',
    ]);
    const ssh = {
      ...outbound,
      protocol: 'tcp' as const,
      destinationPort: '22',
      destination: '10.0.0.0/8',
    };
    expect(ruleSummary(t, ssh, context)[0]).toBe(
      'Traffic from Web server (192.168.1.20) to 10.0.0.0/8 on TCP port 22 goes through the VPN with the VPN address as sender.',
    );
  });

  it('describes blocks and rules that are off', () => {
    expect(ruleSummary(t, block, context)).toEqual([
      'Connections from 198.51.100.7 to this device (192.168.1.10) are dropped silently.',
    ]);
    const reject = {
      ...block,
      action: 'reject' as const,
      protocol: 'tcp' as const,
      destinationPort: '22',
    };
    expect(ruleSummary(t, reject, context)).toEqual([
      'Connections from 198.51.100.7 to this device (192.168.1.10) on TCP port 22 are refused.',
    ]);
    expect(ruleSummary(t, { ...toHost, enabled: false }, context)).toContain(
      'The rule is off and does nothing.',
    );
  });
});

describe('ruleCreates', () => {
  it('lists the input filter of a rule to this device', () => {
    expect(ruleCreates(t, toHost, context)).toEqual([
      'Input filter: allow TCP 443 from any sender to 192.168.1.10',
    ]);
    expect(ruleCreates(t, block, context)).toEqual([
      'Input filter: drop any protocol from 198.51.100.7 to 192.168.1.10',
    ]);
  });

  it('lists filter, DNAT, masquerade and reply route of a port forward', () => {
    expect(ruleCreates(t, forward, context)).toEqual([
      'Forward filter: allow TCP 443 from 203.0.113.0/24 to 192.168.1.20',
      'Destination NAT: TCP 4444 on the VPN address goes to 192.168.1.20:443',
      'Masquerade toward the local LAN: 192.168.1.20 sees this device as the sender',
      'Policy route: replies from 192.168.1.20 leave through the VPN',
    ]);
    const keep = { ...forward, keepSourceAddress: true, destinationPort: '', publicPort: '' };
    expect(ruleCreates(t, keep, context)).toEqual([
      'Forward filter: allow TCP any port from 203.0.113.0/24 to 192.168.1.20',
      'Destination NAT: TCP any port on the VPN address goes to 192.168.1.20',
      'Policy route: replies from 192.168.1.20 leave through the VPN',
    ]);
  });

  it('lists policy route, filter and masquerade of an outbound rule', () => {
    expect(ruleCreates(t, outbound, context)).toEqual([
      'Policy route: traffic from 192.168.1.20 to any address behind the VPN uses the VPN routing table',
      'Forward filter: allow any protocol from 192.168.1.20 to any address behind the VPN',
      'Masquerade on the VPN side: the VPN address becomes the sender',
    ]);
  });

  it('creates nothing while the rule is off', () => {
    expect(ruleCreates(t, { ...forward, enabled: false }, context)).toEqual([
      'Nothing while the rule is off.',
    ]);
  });
});

describe('flowEndpoints', () => {
  it('highlights the LAN device on either side', () => {
    expect(flowEndpoints(t, forward, context)).toEqual([
      { zone: 'vpn', label: '203.0.113.0/24', accent: false },
      { zone: 'lan', label: 'Web server', accent: true },
    ]);
    expect(flowEndpoints(t, toHost, context)[1].label).toBe('This device');
    expect(flowEndpoints(t, outbound, context)).toEqual([
      { zone: 'lan', label: 'Web server', accent: true },
      { zone: 'vpn', label: 'any', accent: false },
    ]);
    expect(flowEndpoints(t, newDraft('inbound'), context)).toEqual([
      { zone: 'vpn', label: 'any', accent: false },
      { zone: 'lan', label: 'not set', accent: true },
    ]);
  });
});

describe('ruleLine', () => {
  it('names the service and notable options in plain words', () => {
    expect(ruleLine(t, forward, context)).toBe('Web · HTTPS (TCP 443) · VPN port 4444');
    const kept = { ...forward, keepSourceAddress: true, enabled: false, publicPort: '' };
    expect(ruleLine(t, kept, context)).toBe('Web · HTTPS (TCP 443) · sender kept · off');
    expect(ruleLine(t, block, context)).toBe('Block · all ports · Drop');
    expect(ruleLine(t, { ...outbound, protocol: 'esp' }, context)).toBe('Out · ESP');
  });
});

describe('suggestedName', () => {
  it('joins device and service', () => {
    expect(suggestedName(t, forward, 'https', context)).toBe('Web server HTTPS');
    expect(suggestedName(t, toHost, 'ssh', context)).toBe('This device SSH');
    expect(suggestedName(t, newDraft('inbound'), 'all', context)).toBe('All ports');
    const custom = {
      ...forward,
      destination: '192.168.1.30',
      protocol: 'udp' as const,
      destinationPort: '1194',
    };
    expect(suggestedName(t, custom, 'custom', context)).toBe('192.168.1.30 UDP 1194');
  });
});
