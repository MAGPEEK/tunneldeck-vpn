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

/** Mirrors internal/vpn/ipsec/schema.go Describe(). */
export const IPSEC_SCHEMA: FormSchema = {
  sections: [
    {
      key: 'gateway',
      labelKey: 'ipsec.section.gateway',
      fields: [
        {
          key: 'template',
          type: 'select',
          labelKey: 'ipsec.template',
          options: [
            {
              value: 'generic',
              labelKey: 'ipsec.template.generic',
              presets: {
                espProposals: [
                  'aes256gcm16-aes128gcm16-chacha20poly1305-curve25519-ecp256-modp3072-modp2048',
                  'aes256-aes128-sha256-curve25519-ecp256-modp3072-modp2048',
                ],
                ikeProposals: [
                  'aes256gcm16-aes128gcm16-prfsha384-prfsha256-curve25519-ecp384-ecp256-modp3072-modp2048',
                  'aes256-aes128-sha384-sha256-curve25519-ecp384-ecp256-modp3072-modp2048',
                ],
                ikeVersion: 'ikev2',
              },
            },
            {
              value: 'lancom',
              labelKey: 'ipsec.template.lancom',
              presets: {
                espProposals: ['aes256gcm16-ecp256-modp2048', 'aes256-sha256-modp2048'],
                ikeProposals: ['aes256gcm16-prfsha256-ecp256-modp2048', 'aes256-sha256-modp2048'],
                ikeVersion: 'ikev2',
              },
            },
            {
              value: 'fritzbox',
              labelKey: 'ipsec.template.fritzbox',
              presets: {
                espProposals: ['aes256-sha512-sha256-modp2048'],
                ikeProposals: ['aes256-sha512-sha256-modp2048'],
                ikeVersion: 'ikev2',
              },
            },
            {
              value: 'fritzboxUser',
              labelKey: 'ipsec.template.fritzboxUser',
              presets: {
                authMethod: 'psk',
                espProposals: ['aes256-sha512', 'aes256-sha1'],
                ikeProposals: [
                  'aes256-sha512-modp2048',
                  'aes256-sha512-modp1024',
                  'aes256-sha1-modp1024',
                ],
                ikeVersion: 'ikev1',
                mode: 'virtualIp',
              },
            },
            {
              value: 'opnsense',
              labelKey: 'ipsec.template.opnsense',
              presets: {
                espProposals: [
                  'aes256gcm16-aes128gcm16-chacha20poly1305-curve25519-ecp256-modp3072-modp2048',
                  'aes256-aes128-sha256-curve25519-ecp256-modp3072-modp2048',
                ],
                ikeProposals: [
                  'aes256gcm16-aes128gcm16-prfsha384-prfsha256-curve25519-ecp384-ecp256-modp3072-modp2048',
                  'aes256-aes128-sha384-sha256-curve25519-ecp384-ecp256-modp3072-modp2048',
                ],
                ikeVersion: 'ikev2',
              },
            },
          ],
          default: 'generic',
        },
        {
          key: 'gateway',
          type: 'text',
          labelKey: 'ipsec.gateway',
          required: true,
          placeholder: 'vpn.example.com',
        },
        {
          key: 'ikeVersion',
          type: 'select',
          labelKey: 'ipsec.ikeVersion',
          options: [
            {
              value: 'ikev2',
              labelKey: 'ipsec.ikeVersion.ikev2',
            },
            {
              value: 'ikev1',
              labelKey: 'ipsec.ikeVersion.ikev1',
            },
          ],
          default: 'ikev2',
        },
        {
          key: 'mode',
          type: 'select',
          labelKey: 'ipsec.mode',
          options: [
            {
              value: 'virtualIp',
              labelKey: 'ipsec.mode.virtualIp',
            },
            {
              value: 'netToNet',
              labelKey: 'ipsec.mode.netToNet',
            },
          ],
          default: 'virtualIp',
        },
        {
          key: 'localSubnets',
          type: 'stringList',
          labelKey: 'ipsec.localSubnets',
          required: true,
          visibleWhen: {
            key: 'mode',
            equals: ['netToNet'],
          },
          placeholder: '192.168.1.0/24',
        },
        {
          key: 'remoteSubnets',
          type: 'stringList',
          labelKey: 'ipsec.remoteSubnets',
          required: true,
          default: ['0.0.0.0/0'],
          placeholder: '10.20.0.0/16',
        },
      ],
    },
    {
      key: 'authentication',
      labelKey: 'ipsec.section.authentication',
      fields: [
        {
          key: 'authMethod',
          type: 'select',
          labelKey: 'ipsec.authMethod',
          options: [
            {
              value: 'psk',
              labelKey: 'ipsec.authMethod.psk',
            },
            {
              value: 'certificate',
              labelKey: 'ipsec.authMethod.certificate',
            },
            {
              value: 'eapMschapv2',
              labelKey: 'ipsec.authMethod.eapMschapv2',
            },
          ],
          default: 'psk',
        },
        {
          key: 'psk',
          type: 'secret',
          labelKey: 'ipsec.psk',
          required: true,
          visibleWhen: {
            key: 'authMethod',
            equals: ['psk'],
          },
        },
        {
          key: 'username',
          type: 'text',
          labelKey: 'ipsec.username',
          required: true,
          visibleWhen: {
            key: 'authMethod',
            equals: ['eapMschapv2'],
          },
        },
        {
          key: 'eapPassword',
          type: 'secret',
          labelKey: 'ipsec.eapPassword',
          required: true,
          visibleWhen: {
            key: 'authMethod',
            equals: ['eapMschapv2'],
          },
        },
        {
          key: 'xauthUsername',
          type: 'text',
          labelKey: 'ipsec.xauthUsername',
          required: true,
          visibleWhen: {
            key: 'ikeVersion',
            equals: ['ikev1'],
          },
        },
        {
          key: 'xauthPassword',
          type: 'secret',
          labelKey: 'ipsec.xauthPassword',
          required: true,
          visibleWhen: {
            key: 'ikeVersion',
            equals: ['ikev1'],
          },
        },
        {
          key: 'caCert',
          type: 'textarea',
          labelKey: 'ipsec.caCert',
          required: true,
          visibleWhen: {
            key: 'authMethod',
            equals: ['certificate', 'eapMschapv2'],
          },
        },
        {
          key: 'clientCert',
          type: 'textarea',
          labelKey: 'ipsec.clientCert',
          visibleWhen: {
            key: 'authMethod',
            equals: ['certificate'],
          },
        },
        {
          key: 'clientKey',
          type: 'secret',
          labelKey: 'ipsec.clientKey',
          multiline: true,
          visibleWhen: {
            key: 'authMethod',
            equals: ['certificate'],
          },
        },
        {
          key: 'pkcs12',
          type: 'secret',
          labelKey: 'ipsec.pkcs12',
          multiline: true,
          visibleWhen: {
            key: 'authMethod',
            equals: ['certificate'],
          },
          encoding: 'base64',
        },
        {
          key: 'pkcs12Password',
          type: 'secret',
          labelKey: 'ipsec.pkcs12Password',
          visibleWhen: {
            secret: 'pkcs12',
          },
        },
        {
          key: 'localId',
          type: 'text',
          labelKey: 'ipsec.localId',
          placeholder: 'client.example.com',
        },
        {
          key: 'remoteId',
          type: 'text',
          labelKey: 'ipsec.remoteId',
          placeholder: 'vpn.example.com',
        },
      ],
    },
    {
      key: 'encryption',
      labelKey: 'ipsec.section.encryption',
      fields: [
        {
          key: 'ikeProposals',
          type: 'stringList',
          labelKey: 'ipsec.ikeProposals',
          default: [
            'aes256gcm16-aes128gcm16-prfsha384-prfsha256-curve25519-ecp384-ecp256-modp3072-modp2048',
            'aes256-aes128-sha384-sha256-curve25519-ecp384-ecp256-modp3072-modp2048',
          ],
        },
        {
          key: 'espProposals',
          type: 'stringList',
          labelKey: 'ipsec.espProposals',
          default: [
            'aes256gcm16-aes128gcm16-chacha20poly1305-curve25519-ecp256-modp3072-modp2048',
            'aes256-aes128-sha256-curve25519-ecp256-modp3072-modp2048',
          ],
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
