import type { Advisory } from '../../../api/profiles';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { problem, type MockRoutes } from '../../../test/fetchMock';
import {
  DRIVERS,
  IPSEC_SCHEMA,
  WIREGUARD_SCHEMA,
  makeFirewall,
  makeProfile,
  makeStatus,
} from '../../../test/fixtures';
import { SIGNED_IN, renderApp } from '../../../test/renderApp';

const SYSTEM = {
  version: '1.0.0',
  listenAddress: '192.168.1.2:8194',
  serverTime: '2026-11-25T10:00:00Z',
  timeZone: 'Europe/Berlin',
  checks: [],
};

const mdexAdvisories: Advisory[] = [
  { code: 'unencrypted_data_channel', severity: 'danger', field: 'cipher' },
  { code: 'fragment_in_use', severity: 'info', field: 'extraOptions' },
  { code: 'no_dco', severity: 'info' },
];

function routes(overrides: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/drivers': { body: DRIVERS },
    'GET /api/system': { body: SYSTEM },
    'GET /api/connection': { body: makeStatus() },
    'GET /api/profiles': { body: [] },
    ...overrides,
  };
}

function submitForm() {
  const form = screen.getByRole('button', { name: 'Save' }).closest('form');
  if (!form) throw new Error('no form');
  fireEvent.submit(form);
}

function change(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function bodyOf(fetchMock: ReturnType<typeof renderApp>['fetchMock'], method: string, url: string) {
  const call = fetchMock.mock.calls.find(([u, init]) => u === url && init?.method === method);
  return JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>;
}

describe('new profile', () => {
  it('offers OpenVPN and shows WireGuard and IPsec as planned', async () => {
    renderApp(routes(), '/profiles/new');
    const group = await screen.findByRole('group', { name: 'Protocol' });
    expect(within(group).getByRole('radio', { name: 'OpenVPN' })).toBeChecked();
    expect(within(group).getByRole('radio', { name: /WireGuard/ })).toBeDisabled();
    expect(within(group).getByRole('radio', { name: /IPsec\/IKEv2/ })).toBeDisabled();
    expect(within(group).getAllByText('Planned')).toHaveLength(2);
    expect(screen.getByText('Server time zone: Europe/Berlin')).toBeInTheDocument();
  });

  it('keeps a setting and a secret loaded from files at the same time', async () => {
    const created = makeProfile({ id: 'new1', name: 'files' });
    const { fetchMock } = renderApp(
      routes({
        'POST /api/profiles': { status: 201, body: created },
        'GET /api/profiles/new1': { body: created },
      }),
      '/profiles/new',
    );
    await screen.findByLabelText('Server address');
    change('Name', 'files');
    change('Server address', 'vpn.example.com');
    change('Username', 'u');
    change('Password', 'p');
    const ca = '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n';
    const ta = '-----BEGIN OpenVPN Static key V1-----\n';

    fireEvent.change(screen.getByLabelText('Load CA certificate from a file'), {
      target: { files: [new File([ca], 'ca.crt')] },
    });
    fireEvent.change(screen.getByLabelText('Load TLS auth key from a file'), {
      target: { files: [new File([ta], 'ta.key')] },
    });
    await waitFor(() => expect(screen.getByLabelText('TLS auth key')).toHaveValue(ta));
    expect(screen.getByLabelText('CA certificate')).toHaveValue(ca);
    submitForm();

    await screen.findByRole('heading', { level: 1, name: 'Edit profile' });
    const body = bodyOf(fetchMock, 'POST', '/api/profiles');
    expect(body.settings).toMatchObject({ caCert: ca });
    expect(body.secrets).toMatchObject({ tlsAuthKey: ta });
  });

  it('creates the RUT240-style profile and shows its danger advisory prominently', async () => {
    const created = makeProfile({ id: 'new1', name: 'mdex', advisories: mdexAdvisories });
    const { fetchMock } = renderApp(
      routes({
        'POST /api/profiles': { status: 201, body: created },
        'GET /api/profiles/new1': { body: created },
      }),
      '/profiles/new',
    );
    await screen.findByLabelText('Server address');

    change('Name', 'mdex');
    change('Server address', 'publicip20.mdex.de');
    change('Username', 'test-user');
    change('Password', 'test-password');
    change('CA certificate', '-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----');
    change('Data channel cipher', 'none');
    change('Authentication digest', 'none');
    const list = screen.getByRole('group', { name: 'Extra options' });
    [
      'tun-mtu 1500',
      'fragment 1448',
      'mssfix',
      'float',
      'reneg-sec 86400',
      'explicit-exit-notify 2',
    ].forEach((line, index) => {
      if (index > 0) fireEvent.click(within(list).getByRole('button', { name: 'Add line' }));
      fireEvent.change(
        within(list).getByRole('textbox', { name: `Extra options, line ${index + 1}` }),
        { target: { value: line } },
      );
    });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Reconnect once a day' }));
    change('Time', '03:15');
    submitForm();

    expect(
      await screen.findByRole('heading', { level: 1, name: 'Edit profile' }),
    ).toBeInTheDocument();
    expect(bodyOf(fetchMock, 'POST', '/api/profiles')).toEqual({
      name: 'mdex',
      protocol: 'openvpn',
      dailyReconnect: { enabled: true, time: '03:15' },
      publicAddress: '',
      settings: {
        remoteHost: 'publicip20.mdex.de',
        port: 1194,
        proto: 'udp',
        authMode: 'password',
        username: 'test-user',
        caCert: '-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----',
        cipher: 'none',
        authDigest: 'none',
        compression: 'none',
        verifyServerCertUsage: true,
        resolveRetry: 'infinite',
        extraOptions: [
          'tun-mtu 1500',
          'fragment 1448',
          'mssfix',
          'float',
          'reneg-sec 86400',
          'explicit-exit-notify 2',
        ],
      },
      secrets: { password: 'test-password' },
      clearSecrets: [],
    });
    expect(await screen.findByText('Profile saved.')).toBeInTheDocument();
    const danger = screen.getByText('Traffic is not encrypted').closest('[data-tone]');
    expect(danger).toHaveAttribute('data-tone', 'danger');
    expect(danger).toHaveTextContent('The data channel uses no cipher');
    expect(screen.getByText('Recommendations')).toBeInTheDocument();
  });

  it('shows server validation errors under the matching fields', async () => {
    renderApp(
      routes({
        'POST /api/profiles': problem(422, 'validation_failed', 'invalid', {
          fields: {
            name: 'must be between 1 and 64 characters',
            'settings.remoteHost': 'must be a host name or an IP address',
            password: 'is required',
            'dailyReconnect.time': 'must be a time in HH:MM format',
            protocol: 'is not supported',
          },
        }),
      }),
      '/profiles/new',
    );
    await screen.findByLabelText('Server address');
    submitForm();

    expect(await screen.findByLabelText('Name')).toHaveAccessibleDescription(
      'must be between 1 and 64 characters',
    );
    expect(screen.getByLabelText('Server address')).toHaveAccessibleDescription(
      'must be a host name or an IP address',
    );
    expect(screen.getByLabelText('Password')).toHaveAccessibleDescription('is required');
    expect(screen.getByLabelText('Time')).toHaveAccessibleDescription(/HH:MM/);
    expect(screen.getByRole('alert')).toHaveTextContent('protocol: is not supported');
  });

  it('translates coded server validation errors', async () => {
    renderApp(
      routes({
        'POST /api/profiles': problem(422, 'validation_failed', 'invalid', {
          fields: {
            name: 'must be between 1 and 64 characters',
            'settings.remoteHost': 'must be a host name or an IP address',
          },
          fieldCodes: {
            name: { code: 'length_between', params: { min: '1', max: '64' } },
            'settings.remoteHost': { code: 'host_invalid' },
          },
        }),
      }),
      '/profiles/new',
    );
    await screen.findByLabelText('Server address');
    submitForm();

    expect(await screen.findByLabelText('Name')).toHaveAccessibleDescription(
      'Between 1 and 64 characters.',
    );
    expect(screen.getByLabelText('Server address')).toHaveAccessibleDescription(
      'Enter a host name or an IP address.',
    );
  });
});

describe('edit profile', () => {
  const profile = makeProfile({ advisories: mdexAdvisories });

  it('edits and sends the public address with its hint and server error', async () => {
    const { fetchMock } = renderApp(
      routes({
        'GET /api/profiles/p1': { body: { ...profile, publicAddress: '203.0.113.10' } },
        'PUT /api/profiles/p1': problem(422, 'validation_failed', 'invalid', {
          fields: { publicAddress: 'must be an IPv4 address or a host name' },
          fieldCodes: { publicAddress: { code: 'public_address_invalid' } },
        }),
      }),
      '/profiles/p1',
    );
    const label = 'Public address of this connection (optional)';
    expect(await screen.findByLabelText(label)).toHaveValue('203.0.113.10');
    expect(screen.getByRole('heading', { name: 'Access' })).toBeInTheDocument();
    change(label, ' vpn.example.com ');
    submitForm();

    expect(await screen.findByLabelText(label)).toHaveAccessibleDescription(
      /TunnelDeck-VPN cannot detect it itself..*Enter an IPv4 address or a host name/,
    );
    expect(bodyOf(fetchMock, 'PUT', '/api/profiles/p1').publicAddress).toBe('vpn.example.com');
  });

  it('keeps stored secrets, replaces on request and tells that changes apply on the next connect', async () => {
    const { fetchMock } = renderApp(
      routes({
        'GET /api/profiles/p1': { body: profile },
        'PUT /api/profiles/p1': { body: profile },
        'GET /api/connection': {
          body: makeStatus({ state: 'connected', profileId: 'p1', profileName: 'Office' }),
        },
        'POST /api/connection/reconnect': {
          status: 202,
          body: makeStatus({ state: 'reconnecting', profileId: 'p1' }),
        },
      }),
      '/profiles/p1',
    );
    expect(await screen.findByLabelText('Name')).toHaveValue('Office');
    expect(screen.queryByRole('group', { name: 'Protocol' })).not.toBeInTheDocument();
    expect(screen.getByText('Traffic is not encrypted')).toBeInTheDocument();
    const password = screen.getByRole('group', { name: 'Password' });
    expect(within(password).getByText('Stored')).toBeInTheDocument();

    submitForm();
    expect(await screen.findByText('Changes apply on the next connect.')).toBeInTheDocument();
    expect(bodyOf(fetchMock, 'PUT', '/api/profiles/p1').secrets).toEqual({});

    fireEvent.click(screen.getByRole('button', { name: 'Reconnect now' }));
    await screen.findByText('Profile saved.');
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/connection/reconnect',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('sends a replaced secret', async () => {
    const { fetchMock } = renderApp(
      routes({
        'GET /api/profiles/p1': { body: profile },
        'PUT /api/profiles/p1': { body: profile },
      }),
      '/profiles/p1',
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Replace' }));
    change('Password', 'changed');
    submitForm();
    await screen.findByText('Profile saved.');
    expect(bodyOf(fetchMock, 'PUT', '/api/profiles/p1').secrets).toEqual({ password: 'changed' });
    expect(screen.queryByText('Changes apply on the next connect.')).not.toBeInTheDocument();
  });
});

describe('WireGuard profile', () => {
  const drivers = [...DRIVERS, { protocol: 'wireguard', schema: WIREGUARD_SCHEMA }];
  const pair = { privateKey: 'bmV3LXByaXZhdGU=', publicKey: 'bmV3LXB1YmxpYw==' };
  const hint = "Enter this public key on the server as the peer's public key.";
  const tunnel = makeProfile({
    id: 'wg1',
    name: 'Tunnel',
    protocol: 'wireguard',
    settings: {
      address: '10.66.0.2/32',
      mtu: 1420,
      peerPublicKey: 'c2VydmVy',
      endpoint: 'wg.example.com:51820',
      allowedIps: ['0.0.0.0/0'],
      persistentKeepalive: 25,
    },
    secrets: { privateKey: { hasValue: true } },
    derived: { publicKey: 'c3RvcmVkLXB1YmxpYw==' },
  });

  function wgRoutes(overrides: MockRoutes = {}): MockRoutes {
    return routes({
      'GET /api/drivers': { body: drivers },
      'POST /api/drivers/wireguard/keypair': { body: pair },
      ...overrides,
    });
  }

  async function chooseWireGuard() {
    const group = await screen.findByRole('group', { name: 'Protocol' });
    fireEvent.click(within(group).getByRole('radio', { name: 'WireGuard' }));
  }

  it('offers WireGuard next to OpenVPN and switches to its form', async () => {
    renderApp(wgRoutes(), '/profiles/new');
    const group = await screen.findByRole('group', { name: 'Protocol' });
    expect(within(group).getByRole('radio', { name: 'WireGuard' })).toBeEnabled();
    expect(within(group).getAllByText('Planned')).toHaveLength(1);

    await chooseWireGuard();
    expect(screen.getByLabelText('Server address (host:port)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Generate key pair' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Public key')).not.toBeInTheDocument();
  });

  it('generates a key pair, shows the public key and sends the private key on save', async () => {
    const created = { ...tunnel, id: 'new1' };
    const { fetchMock } = renderApp(
      wgRoutes({
        'POST /api/profiles': { status: 201, body: created },
        'GET /api/profiles/new1': { body: created },
      }),
      '/profiles/new',
    );
    await chooseWireGuard();
    fireEvent.click(screen.getByRole('button', { name: 'Generate key pair' }));

    expect(await screen.findByLabelText('Public key')).toHaveValue(pair.publicKey);
    expect(screen.getByLabelText('Public key')).toHaveAccessibleDescription(hint);
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(screen.getByLabelText('Private key')).toHaveValue(pair.privateKey);

    change('Private key', 'dHlwZWQ=');
    expect(screen.queryByLabelText('Public key')).not.toBeInTheDocument();
    change('Private key', pair.privateKey);

    change('Name', 'Tunnel');
    change('Tunnel address (IPv4 with prefix length)', '10.66.0.2/32');
    change('Server public key', 'c2VydmVy');
    change('Server address (host:port)', 'wg.example.com:51820');
    submitForm();
    await screen.findByText('Profile saved.');
    const body = bodyOf(fetchMock, 'POST', '/api/profiles');
    expect(body.protocol).toBe('wireguard');
    expect(body.secrets).toEqual({ privateKey: pair.privateKey });
  });

  it('shows the public key of the stored private key read-only with Copy', async () => {
    renderApp(wgRoutes({ 'GET /api/profiles/wg1': { body: tunnel } }), '/profiles/wg1');
    const publicKey = await screen.findByLabelText('Public key');
    expect(publicKey).toHaveValue('c3RvcmVkLXB1YmxpYw==');
    expect(publicKey).toHaveAttribute('readonly');
    expect(publicKey).toHaveAccessibleDescription(hint);
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
  });

  it('asks before replacing a stored private key', async () => {
    const { fetchMock } = renderApp(
      wgRoutes({
        'GET /api/profiles/wg1': { body: tunnel },
        'PUT /api/profiles/wg1': { body: tunnel },
      }),
      '/profiles/wg1',
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Generate key pair' }));
    const confirm = screen.getByRole('group', { name: 'Confirm replacing the private key' });
    fireEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }));
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/keypair'))).toBe(false);
    expect(screen.getByLabelText('Public key')).toHaveValue('c3RvcmVkLXB1YmxpYw==');

    fireEvent.click(screen.getByRole('button', { name: 'Generate key pair' }));
    fireEvent.click(screen.getByRole('button', { name: 'Replace key' }));
    expect(await screen.findByLabelText('Public key')).toHaveValue(pair.publicKey);
    expect(screen.getByLabelText('Private key')).toHaveValue(pair.privateKey);

    submitForm();
    await screen.findByText('Profile saved.');
    expect(bodyOf(fetchMock, 'PUT', '/api/profiles/wg1').secrets).toEqual({
      privateKey: pair.privateKey,
    });
  });

  it('shows why generating failed', async () => {
    renderApp(
      wgRoutes({ 'POST /api/drivers/wireguard/keypair': 'network-error' }),
      '/profiles/new',
    );
    await chooseWireGuard();
    fireEvent.click(screen.getByRole('button', { name: 'Generate key pair' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByLabelText('Private key')).toHaveValue('');
  });
});

describe('IPsec profile', () => {
  const drivers = [...DRIVERS, { protocol: 'ipsec', schema: IPSEC_SCHEMA }];
  const fritzHint = /FRITZ!Box: Internet → Permit Access → VPN \(IPSec\) → user/;

  function ipsecRoutes(overrides: MockRoutes = {}): MockRoutes {
    return routes({
      'GET /api/drivers': { body: drivers },
      'GET /api/firewall': { body: makeFirewall({ hostAddresses: ['192.168.1.10'] }) },
      ...overrides,
    });
  }

  async function chooseIpsec() {
    const group = await screen.findByRole('group', { name: 'Protocol' });
    fireEvent.click(within(group).getByRole('radio', { name: 'IPsec/IKEv2' }));
  }

  it('offers IPsec next to OpenVPN and switches to its form', async () => {
    renderApp(ipsecRoutes(), '/profiles/new');
    const group = await screen.findByRole('group', { name: 'Protocol' });
    expect(within(group).getByRole('radio', { name: 'IPsec/IKEv2' })).toBeEnabled();

    await chooseIpsec();
    expect(screen.getByLabelText('Gateway type')).toHaveValue('generic');
    expect(screen.getByLabelText('IKE version')).toHaveValue('ikev2');
    expect(screen.getByText(/defaults recommended by RFC 8247/)).toBeInTheDocument();
    expect(screen.queryByText('IKEv1 Aggressive Mode is insecure')).not.toBeInTheDocument();
  });

  it('pre-fills the FRITZ!Box user access, warns about IKEv1 and saves it', async () => {
    const created = makeProfile({ id: 'new1', name: 'Fritz', protocol: 'ipsec' });
    const { fetchMock } = renderApp(
      ipsecRoutes({
        'POST /api/profiles': { status: 201, body: created },
        'GET /api/profiles/new1': { body: created },
      }),
      '/profiles/new',
    );
    await chooseIpsec();

    change('Gateway type', 'fritzboxUser');
    expect(screen.getByLabelText('IKE version')).toHaveValue('ikev1');
    expect(screen.getByText(fritzHint)).toBeInTheDocument();
    expect(screen.getByText('IKEv1 Aggressive Mode is insecure')).toBeInTheDocument();
    expect(screen.queryByText(/Your own values were kept/)).not.toBeInTheDocument();

    change('Name', 'Fritz');
    change('Gateway address', 'example.myfritz.net');
    change('Pre-shared key', 'shared-secret-from-vpn-data');
    change('XAuth username', 'vpnuser');
    change('XAuth password', 'vpnpassword');
    submitForm();

    await screen.findByText('Profile saved.');
    const body = bodyOf(fetchMock, 'POST', '/api/profiles');
    expect(body.protocol).toBe('ipsec');
    expect(body.settings).toMatchObject({
      template: 'fritzboxUser',
      gateway: 'example.myfritz.net',
      ikeVersion: 'ikev1',
      mode: 'virtualIp',
      xauthUsername: 'vpnuser',
      ikeProposals: ['aes256-sha512-modp2048', 'aes256-sha512-modp1024', 'aes256-sha1-modp1024'],
    });
    expect(body.secrets).toEqual({
      psk: 'shared-secret-from-vpn-data',
      xauthPassword: 'vpnpassword',
    });
  });

  it('keeps values the user changed and applies the template on request', async () => {
    renderApp(ipsecRoutes(), '/profiles/new');
    await chooseIpsec();

    change('IKE proposals, line 1', 'aes128-sha256-modp2048');
    change('Gateway type', 'lancom');

    expect(screen.getByLabelText('IKE proposals, line 1')).toHaveValue('aes128-sha256-modp2048');
    expect(screen.getByLabelText('ESP proposals, line 1')).toHaveValue(
      'aes256gcm16-ecp256-modp2048',
    );
    expect(screen.getByText('Your own values were kept for: IKE proposals.')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Use template values' }));
    expect(screen.getByLabelText('IKE proposals, line 1')).toHaveValue(
      'aes256gcm16-prfsha256-ecp256-modp2048',
    );
    expect(screen.queryByText(/Your own values were kept/)).not.toBeInTheDocument();
  });

  it('tells in net-to-net mode which static route the LAN router needs', async () => {
    renderApp(ipsecRoutes(), '/profiles/new');
    await chooseIpsec();
    expect(screen.queryByText('Static route needed in your LAN router')).not.toBeInTheDocument();

    change('Mode', 'netToNet');
    change('Remote subnets (one IPv4 network per line), line 1', '10.20.0.0/16');

    expect(screen.getByText('Static route needed in your LAN router')).toBeInTheDocument();
    expect(
      await screen.findByText(
        /remote subnets \(10\.20\.0\.0\/16\) with this device \(192\.168\.1\.10\)/,
      ),
    ).toBeInTheDocument();
  });

  it('shows the saved IKEv1 danger advisory once, above the form', async () => {
    const saved = makeProfile({
      id: 'ip1',
      name: 'Fritz',
      protocol: 'ipsec',
      settings: { template: 'fritzboxUser', gateway: 'example.myfritz.net', ikeVersion: 'ikev1' },
      advisories: [{ code: 'ikev1_aggressive', severity: 'danger', field: 'ikeVersion' }],
    });
    renderApp(ipsecRoutes({ 'GET /api/profiles/ip1': { body: saved } }), '/profiles/ip1');
    await screen.findByLabelText('Gateway address');
    expect(screen.getAllByText('IKEv1 Aggressive Mode is insecure')).toHaveLength(1);
  });
});
