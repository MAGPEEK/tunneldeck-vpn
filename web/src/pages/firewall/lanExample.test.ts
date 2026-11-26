import { describe, expect, it } from 'vitest';
import { firstLanExample, lanExample } from './lanExample';

describe('lanExample', () => {
  it.each([
    { subnet: '192.168.2.0/24', hostPart: 'x', want: '192.168.2.x' },
    { subnet: '192.168.2.0/24', hostPart: '20', want: '192.168.2.20' },
    { subnet: '10.1.0.0/16', hostPart: 'x', want: '10.1.x.x' },
    { subnet: '10.1.0.0/16', hostPart: '20', want: '10.1.x.20' },
    { subnet: '10.0.0.0/8', hostPart: 'x', want: '10.x.x.x' },
    { subnet: '192.168.2.0/23', hostPart: 'x', want: '192.168.2.x' },
    { subnet: '172.16.0.0/12', hostPart: 'x', want: '172.16.x.x' },
    { subnet: '192.168.2.16/28', hostPart: 'x', want: '192.168.2.17' },
    { subnet: '192.168.2.64/26', hostPart: 'x', want: '192.168.2.65' },
    { subnet: '192.168.2.6/31', hostPart: 'x', want: '192.168.2.6' },
    { subnet: '192.168.2.7/32', hostPart: 'x', want: '192.168.2.7' },
    { subnet: ' 192.168.2.0/24 ', hostPart: 'x', want: '192.168.2.x' },
  ])('renders $subnet with host part $hostPart as $want', ({ subnet, hostPart, want }) => {
    expect(lanExample(subnet, hostPart)).toBe(want);
  });

  it.each([undefined, '', '192.168.2.0', '192.168.2.0/33', '300.1.1.0/24', 'fd00::/64'])(
    'gives nothing for %s',
    (subnet) => {
      expect(lanExample(subnet)).toBeUndefined();
    },
  );

  it('uses "x" as the default host part', () => {
    expect(lanExample('192.168.2.0/24')).toBe('192.168.2.x');
  });
});

describe('firstLanExample', () => {
  it.each([
    { subnets: ['192.168.2.0/24', '10.1.0.0/16'], want: '192.168.2.x' },
    { subnets: ['fd00::/64', '10.1.0.0/16'], want: '10.1.x.x' },
    { subnets: [], want: undefined },
    { subnets: ['not a subnet'], want: undefined },
  ])('picks the first IPv4 subnet of $subnets', ({ subnets, want }) => {
    expect(firstLanExample(subnets)).toBe(want);
  });
});
