import type { ConnectionStatus } from '../api/connection';
import type { FirewallRule, FirewallState } from '../api/firewall';
import type { Driver, FormSchema, Profile } from '../api/profiles';

const passwordModes = ['password', 'certificate+password'];
const certificateModes = ['certificate', 'certificate+password'];

function option(key: string, value: string) {
  return { value, labelKey: `openvpn.${key}.${value}` };
}

/** Mirrors internal/vpn/openvpn/schema.go Describe(). */
export const OPENVPN_SCHEMA: FormSchema = {
  sections: [
    {
      key: 'server',
      labelKey: 'openvpn.section.server',
      fields: [
        {
          key: 'remoteHost',
          type: 'text',
          labelKey: 'openvpn.remoteHost',
          required: true,
          placeholder: 'vpn.example.com',
        },
        { key: 'port', type: 'number', labelKey: 'openvpn.port', required: true, default: 1194 },
        {
          key: 'proto',
          type: 'select',
          labelKey: 'openvpn.proto',
          required: true,
          default: 'udp',
          options: [option('proto', 'udp'), option('proto', 'tcp')],
        },
      ],
    },
    {
      key: 'authentication',
      labelKey: 'openvpn.section.authentication',
      fields: [
        {
          key: 'authMode',
          type: 'select',
          labelKey: 'openvpn.authMode',
          required: true,
          default: 'password',
          options: [
            option('authMode', 'password'),
            option('authMode', 'certificate'),
            option('authMode', 'certificate+password'),
          ],
        },
        {
          key: 'username',
          type: 'text',
          labelKey: 'openvpn.username',
          required: true,
          visibleWhen: { key: 'authMode', equals: passwordModes },
        },
        {
          key: 'password',
          type: 'secret',
          labelKey: 'openvpn.password',
          required: true,
          visibleWhen: { key: 'authMode', equals: passwordModes },
        },
        {
          key: 'caCert',
          type: 'textarea',
          labelKey: 'openvpn.caCert',
          required: true,
          placeholder: '-----BEGIN CERTIFICATE-----',
        },
        {
          key: 'clientCert',
          type: 'textarea',
          labelKey: 'openvpn.clientCert',
          placeholder: '-----BEGIN CERTIFICATE-----',
          visibleWhen: { key: 'authMode', equals: certificateModes },
        },
        {
          key: 'clientKey',
          type: 'secret',
          labelKey: 'openvpn.clientKey',
          multiline: true,
          visibleWhen: { key: 'authMode', equals: certificateModes },
        },
        {
          key: 'pkcs12',
          type: 'secret',
          labelKey: 'openvpn.pkcs12',
          multiline: true,
          encoding: 'base64',
          visibleWhen: { key: 'authMode', equals: certificateModes },
        },
        {
          key: 'keyPassphrase',
          type: 'secret',
          labelKey: 'openvpn.keyPassphrase',
          visibleWhen: { key: 'authMode', equals: certificateModes },
        },
      ],
    },
    {
      key: 'encryption',
      labelKey: 'openvpn.section.encryption',
      fields: [
        { key: 'cipher', type: 'text', labelKey: 'openvpn.cipher', placeholder: 'AES-256-GCM' },
        { key: 'authDigest', type: 'text', labelKey: 'openvpn.authDigest', placeholder: 'SHA256' },
        {
          key: 'compression',
          type: 'select',
          labelKey: 'openvpn.compression',
          required: true,
          default: 'none',
          options: [option('compression', 'none'), option('compression', 'lzo')],
        },
        {
          key: 'verifyServerCertUsage',
          type: 'bool',
          labelKey: 'openvpn.verifyServerCertUsage',
          default: true,
        },
        { key: 'tlsAuthKey', type: 'secret', labelKey: 'openvpn.tlsAuthKey', multiline: true },
        {
          key: 'keyDirection',
          type: 'select',
          labelKey: 'openvpn.keyDirection',
          required: true,
          default: '1',
          visibleWhen: { secret: 'tlsAuthKey' },
          options: [
            option('keyDirection', '1'),
            option('keyDirection', '0'),
            option('keyDirection', 'bidirectional'),
          ],
        },
        { key: 'tlsCryptKey', type: 'secret', labelKey: 'openvpn.tlsCryptKey', multiline: true },
        {
          key: 'tlsCryptV2Key',
          type: 'secret',
          labelKey: 'openvpn.tlsCryptV2Key',
          multiline: true,
        },
      ],
    },
    {
      key: 'advanced',
      labelKey: 'openvpn.section.advanced',
      fields: [
        {
          key: 'resolveRetry',
          type: 'text',
          labelKey: 'openvpn.resolveRetry',
          default: 'infinite',
        },
        { key: 'keepalive', type: 'text', labelKey: 'openvpn.keepalive', placeholder: '10 120' },
        {
          key: 'remoteNetworks',
          type: 'stringList',
          labelKey: 'openvpn.remoteNetworks',
          placeholder: '192.168.100.0/24',
        },
        {
          key: 'extraOptions',
          type: 'stringList',
          labelKey: 'openvpn.extraOptions',
          placeholder: 'tun-mtu 1500',
        },
      ],
    },
  ],
};

/** Mirrors internal/vpn/wireguard/schema.go Describe(). */
export const WIREGUARD_SCHEMA: FormSchema = {
  sections: [
    {
      key: 'interface',
      labelKey: 'wireguard.section.interface',
      fields: [
        { key: 'privateKey', type: 'secret', labelKey: 'wireguard.privateKey', required: true },
        {
          key: 'address',
          type: 'text',
          labelKey: 'wireguard.address',
          required: true,
          placeholder: '10.66.0.2/32',
        },
        { key: 'mtu', type: 'number', labelKey: 'wireguard.mtu', required: true, default: 1420 },
      ],
    },
    {
      key: 'peer',
      labelKey: 'wireguard.section.peer',
      fields: [
        { key: 'peerPublicKey', type: 'text', labelKey: 'wireguard.peerPublicKey', required: true },
        { key: 'presharedKey', type: 'secret', labelKey: 'wireguard.presharedKey' },
        {
          key: 'endpoint',
          type: 'text',
          labelKey: 'wireguard.endpoint',
          required: true,
          placeholder: 'vpn.example.com:51820',
        },
        {
          key: 'allowedIps',
          type: 'stringList',
          labelKey: 'wireguard.allowedIps',
          required: true,
          default: ['0.0.0.0/0'],
          placeholder: '10.66.0.0/24',
        },
        {
          key: 'persistentKeepalive',
          type: 'number',
          labelKey: 'wireguard.persistentKeepalive',
          default: 25,
        },
      ],
    },
  ],
};

export const DRIVERS: Driver[] = [{ protocol: 'openvpn', schema: OPENVPN_SCHEMA }];

export function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    id: 'p1',
    name: 'Office',
    protocol: 'openvpn',
    settings: {
      remoteHost: 'vpn.example.com',
      port: 1194,
      proto: 'udp',
      authMode: 'password',
      username: 'alice',
      caCert: 'CA',
    },
    secrets: { password: { hasValue: true } },
    dailyReconnect: { enabled: false, time: '04:00' },
    createdAt: '2026-11-01T10:00:00Z',
    updatedAt: '2026-11-01T10:00:00Z',
    advisories: [{ code: 'no_dco', severity: 'info' }],
    ...overrides,
  };
}

export function makeStatus(overrides: Partial<ConnectionStatus> = {}): ConnectionStatus {
  return {
    state: 'disconnected',
    since: '2026-11-25T10:00:00Z',
    bytesIn: 0,
    bytesOut: 0,
    rateIn: 0,
    rateOut: 0,
    advisories: [],
    ...overrides,
  };
}

export function makeRule(overrides: Partial<FirewallRule> = {}): FirewallRule {
  return {
    id: 'r1',
    name: 'Admin',
    direction: 'inbound',
    action: 'accept',
    protocol: 'tcp',
    source: '',
    destination: '192.168.1.10',
    destinationPort: { from: 5001 },
    keepSourceAddress: false,
    enabled: true,
    comment: '',
    ...overrides,
  };
}

export function makeFirewall(overrides: Partial<FirewallState> = {}): FirewallState {
  return {
    rules: [makeRule()],
    settings: { dropInvalid: true, mssClamp: true, synFloodProtection: true, pingLimit: true },
    hostAddress: '192.168.1.10',
    hostAddresses: ['192.168.1.10'],
    lanSubnets: ['192.168.1.0/24'],
    ipForward: true,
    counters: null,
    countersAvailable: false,
    protectionsAvailable: { synFlood: 'full', ping: 'full', mssClamp: 'full', ruleCounters: true },
    ...overrides,
  };
}
