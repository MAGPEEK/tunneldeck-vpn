import { describe, expect, it } from 'vitest';
import type { Settings } from '../../api/profiles';
import { profileServer, profileServerHost } from './profileText';

describe('profileServer', () => {
  it.each<[string, Settings, string]>([
    [
      'OpenVPN host and port',
      { remoteHost: 'vpn.example.com', port: 1194 },
      'vpn.example.com:1194',
    ],
    ['OpenVPN IPv6 host', { remoteHost: '2001:db8::1', port: 1194 }, '[2001:db8::1]:1194'],
    ['WireGuard endpoint', { endpoint: 'wg.example.com:51820' }, 'wg.example.com:51820'],
    ['IPsec gateway', { gateway: 'vpn.example.com' }, 'vpn.example.com'],
    ['nothing set', {}, ''],
  ])('shows %s', (_name, settings, server) => {
    expect(profileServer({ settings })).toBe(server);
  });
});

describe('profileServerHost', () => {
  it.each<[string, Settings, string]>([
    ['remoteHost', { remoteHost: 'vpn.example.com', port: 1194 }, 'vpn.example.com'],
    ['endpoint with port', { endpoint: 'wg.example.com:51820' }, 'wg.example.com'],
    ['endpoint without port', { endpoint: 'wg.example.com' }, 'wg.example.com'],
    ['bracketed IPv6 endpoint', { endpoint: '[2001:db8::1]:51820' }, '2001:db8::1'],
    ['IPsec gateway', { gateway: 'office.example.com' }, 'office.example.com'],
    ['nothing set', {}, ''],
  ])('takes the host from %s', (_name, settings, host) => {
    expect(profileServerHost(settings)).toBe(host);
  });
});
