import { describe, expect, it } from 'vitest';
import { profileProtocol } from './profileFile';

describe('profileProtocol', () => {
  it.each([
    ['wg-quick file', '[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = y', 'wireguard'],
    [
      'indented header with CRLF',
      '# provider\r\n  [Interface]  \r\nAddress = 10.0.0.2/32',
      'wireguard',
    ],
    ['peer section only', '[peer]\nEndpoint = vpn.example.com:51820', 'wireguard'],
    ['OpenVPN client file', 'client\nremote vpn.example.com 1194\n<ca>\nX\n</ca>', 'openvpn'],
    ['bracket text inside a line', 'client\n# see [Interface] in the docs', 'openvpn'],
    ['empty text', '', 'openvpn'],
  ])('reads a %s as %s', (_name, text, protocol) => {
    expect(profileProtocol(text)).toBe(protocol);
  });
});
