import { describe, expect, it } from 'vitest';
import type { RemoteAccess } from '../api/remoteAccess';
import { remoteAccessActive, remoteAccessTarget } from './remoteAccessUrl';

describe('remoteAccessTarget', () => {
  const vpn = '172.21.31.170';
  const detected = '46.16.217.194';
  it.each([
    [
      'vpn.example.com',
      detected,
      vpn,
      { url: 'https://vpn.example.com:8443', source: 'publicAddress' },
    ],
    [
      ' 203.0.113.10 ',
      undefined,
      vpn,
      { url: 'https://203.0.113.10:8443', source: 'publicAddress' },
    ],
    ['', detected, vpn, { url: 'https://46.16.217.194:8443', source: 'detected' }],
    [undefined, detected, undefined, { url: 'https://46.16.217.194:8443', source: 'detected' }],
    ['', undefined, vpn, { url: 'https://172.21.31.170:8443', source: 'vpnIp' }],
    [undefined, '', vpn, { url: 'https://172.21.31.170:8443', source: 'vpnIp' }],
    ['', undefined, undefined, undefined],
  ])(
    'uses public address %j, detected IP %j and VPN IP %j',
    (publicAddress, detectedIp, vpnIp, want) => {
      expect(remoteAccessTarget(8443, publicAddress, detectedIp, vpnIp)).toEqual(want);
    },
  );
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
