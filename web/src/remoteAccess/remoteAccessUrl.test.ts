import { describe, expect, it } from 'vitest';
import type { RemoteAccess } from '../api/remoteAccess';
import { remoteAccessActive, remoteAccessTarget } from './remoteAccessUrl';

describe('remoteAccessTarget', () => {
  it.each([
    ['vpn.example.com', '172.21.31.170', { url: 'https://vpn.example.com:8443', fromVpnIp: false }],
    [' 203.0.113.10 ', '172.21.31.170', { url: 'https://203.0.113.10:8443', fromVpnIp: false }],
    ['', '172.21.31.170', { url: 'https://172.21.31.170:8443', fromVpnIp: true }],
    [undefined, '172.21.31.170', { url: 'https://172.21.31.170:8443', fromVpnIp: true }],
    ['', undefined, undefined],
  ])('uses public address %j and VPN IP %j', (publicAddress, vpnIp, want) => {
    expect(remoteAccessTarget(8443, publicAddress, vpnIp)).toEqual(want);
  });
});

describe('remoteAccessActive', () => {
  const remote: RemoteAccess = {
    enabled: true,
    port: 8443,
    certificateSource: 'selfSigned',
    certificate: null,
    listening: true,
  };
  it.each([
    [remote, true],
    [{ ...remote, listening: false }, false],
    [{ ...remote, enabled: false }, false],
    [null, false],
    [undefined, false],
  ])('is %#: %s', (value, want) => {
    expect(remoteAccessActive(value)).toBe(want);
  });
});
