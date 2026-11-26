import { describe, expect, it } from 'vitest';
import { shownPublicIp } from './shownPublicIp';

describe('shownPublicIp', () => {
  it.each([
    ['vpn.example.com', '46.16.217.194', { address: 'vpn.example.com', detected: false }],
    [' 203.0.113.10 ', '46.16.217.194', { address: '203.0.113.10', detected: false }],
    ['', '46.16.217.194', { address: '46.16.217.194', detected: true }],
    [undefined, '46.16.217.194', { address: '46.16.217.194', detected: true }],
    ['  ', undefined, undefined],
    [undefined, '', undefined],
  ])('uses public address %j and detected IP %j', (publicAddress, detectedIp, want) => {
    expect(shownPublicIp(publicAddress, detectedIp)).toEqual(want);
  });
});
