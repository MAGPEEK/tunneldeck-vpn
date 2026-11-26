import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FakeEventSource } from '../../test/fakeEventSource';
import { problem, type MockRoutes } from '../../test/fetchMock';
import { DRIVERS, makeProfile, makeStatus } from '../../test/fixtures';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const profile = makeProfile();

const adminUi = {
  id: 'a',
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
};

const routerOut = {
  ...adminUi,
  id: 'b',
  name: 'Router out',
  direction: 'outbound',
  protocol: 'esp',
  source: '192.168.1.2',
  destination: '0.0.0.0/0',
  destinationPort: undefined,
};

function firewall(overrides: Record<string, unknown> = {}) {
  return {
    rules: [adminUi],
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

function routes(overrides: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/profiles': { body: [profile] },
    'GET /api/connection': { body: makeStatus() },
    'GET /api/firewall': { body: firewall() },
    'GET /api/remote-access': problem(404, 'not_found', 'The resource does not exist.'),
    'GET /api/firewall/devices': {
      body: {
        devices: [
          { address: '192.168.1.2', mac: 'aa:bb:cc:00:00:02', state: 'REACHABLE', onLan: true },
          { address: '192.168.1.3', mac: 'aa:bb:cc:00:00:03', state: 'STALE', onLan: true },
          { address: '10.8.0.1', mac: '', state: 'REACHABLE', onLan: false },
        ],
      },
    },
    'GET /api/system': {
      body: {
        version: '0.2.0-alpha.6',
        listenAddress: ':8080',
        serverTime: '2026-11-25T10:00:00Z',
        timeZone: 'UTC',
        checks: [],
      },
    },
    ...overrides,
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('DashboardPage', () => {
  it('shows only the empty state when there are no profiles', async () => {
    renderApp(routes({ 'GET /api/profiles': { body: [] } }));

    expect(
      await screen.findByRole('heading', { name: 'Add your first VPN profile' }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Log' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create manually' }));
    expect(window.location.pathname).toBe('/profiles/new');
  });

  it('loads an .ovpn file from the empty state into the new-profile form', async () => {
    const { fetchMock } = renderApp(
      routes({
        'GET /api/profiles': { body: [] },
        'GET /api/drivers': { body: DRIVERS },
        'POST /api/profiles/import': {
          body: {
            settings: { remoteHost: 'vpn.example.com', authMode: 'password' },
            secrets: {},
            warnings: [],
            missing: ['username', 'password'],
          },
        },
      }),
    );
    await screen.findByRole('heading', { name: 'Add your first VPN profile' });
    expect(screen.getByRole('button', { name: 'Load .ovpn file' })).toBeInTheDocument();
    fireEvent.change(screen.getByTestId('profile-file-input'), {
      target: { files: [new File(['client\nremote vpn.example.com'], 'Office.ovpn')] },
    });

    expect(await screen.findByLabelText('Name')).toHaveValue('Office');
    expect(window.location.pathname).toBe('/profiles/new');
    const call = fetchMock.mock.calls.find(([url]) => url === '/api/profiles/import');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      protocol: 'openvpn',
      text: 'client\nremote vpn.example.com',
    });
  });

  it('explains a file that is not a profile on the empty state', async () => {
    renderApp(routes({ 'GET /api/profiles': { body: [] } }));
    await screen.findByRole('heading', { name: 'Add your first VPN profile' });
    fireEvent.change(screen.getByTestId('profile-file-input'), {
      target: { files: [new File(['x'], 'photo.jpg')] },
    });
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Could not load photo.jpg');
    expect(alert).toHaveTextContent('Only .ovpn or .conf files can be loaded.');
  });

  it('shows the connection line and details, and links to the log', async () => {
    renderApp(routes());

    expect(await screen.findByRole('region', { name: 'Connection details' })).toBeInTheDocument();
    expect(screen.getAllByText('Disconnected').length).toBeGreaterThan(0);
    expect(await screen.findByText('192.168.1.0/24 · 2 devices')).toBeInTheDocument();
    expect(
      await screen.findByText('192.168.1.10 · TunnelDeck-VPN 0.2.0-alpha.6'),
    ).toBeInTheDocument();
    const details = screen.getByRole('region', { name: 'Connection details' });
    expect(within(details).getByText('Received –')).toBeInTheDocument();
    expect(within(details).getByText('1 active rule')).toBeInTheDocument();
    expect(within(details).queryByText('Remote access')).not.toBeInTheDocument();
    expect(within(details).queryByText('Encryption')).not.toBeInTheDocument();
    expect(screen.queryByText(/IP forwarding is off/)).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open firewall' })).toHaveAttribute(
      'href',
      '/firewall',
    );
    expect(screen.getByRole('link', { name: 'Show log' })).toHaveAttribute('href', '/log');
    expect(screen.queryByRole('heading', { name: 'Log' })).not.toBeInTheDocument();
    expect(FakeEventSource.latest().url).toBe('/api/events');
  });

  it('hides the connection line when unchecked in Customize', async () => {
    renderApp(routes());
    await screen.findByRole('region', { name: 'Connection details' });
    expect(screen.getByRole('link', { name: 'Open firewall' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Customize' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Connection line' }));

    expect(screen.queryByRole('link', { name: 'Open firewall' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect' })).toBeInTheDocument();
  });

  it('warns when IP forwarding is off and a rule needs it', async () => {
    renderApp(
      routes({
        'GET /api/firewall': { body: firewall({ rules: [adminUi, routerOut], ipForward: false }) },
      }),
    );
    expect(await screen.findByText('2 active rules')).toBeInTheDocument();
    expect(
      screen.getByText(
        'IP forwarding is off on the host: port forwards and outbound rules do not work.',
      ),
    ).toBeInTheDocument();
  });

  it('does not warn about IP forwarding when only rules to this device exist', async () => {
    renderApp(routes({ 'GET /api/firewall': { body: firewall({ ipForward: false }) } }));
    expect(await screen.findByText('1 active rule')).toBeInTheDocument();
    expect(screen.queryByText(/IP forwarding is off/)).not.toBeInTheDocument();
  });

  it('shows remote access when the build has it', async () => {
    renderApp(
      routes({
        'GET /api/remote-access': {
          body: {
            enabled: true,
            port: 8443,
            certificateSource: 'selfSigned',
            certificate: null,
            listening: true,
          },
        },
      }),
    );
    expect(await screen.findByText('HTTPS on port 8443')).toBeInTheDocument();
    expect(screen.getByText('Remote access on').closest('[data-tone]')).toHaveAttribute(
      'data-tone',
      'accent',
    );
  });

  it('links remote access at the public address of the profile while connected', async () => {
    renderApp(
      routes({
        'GET /api/profiles': { body: [{ ...profile, publicAddress: '203.0.113.10' }] },
        'GET /api/connection': {
          body: makeStatus({ state: 'connected', profileId: 'p1', vpnIp: '172.21.31.170' }),
        },
        'GET /api/remote-access': {
          body: {
            enabled: true,
            port: 8443,
            certificateSource: 'selfSigned',
            certificate: null,
            listening: true,
          },
        },
      }),
    );
    expect(
      await screen.findByRole('link', { name: 'https://203.0.113.10:8443' }),
    ).toBeInTheDocument();
  });

  it('shows no remote access pill while remote access is off or not listening', async () => {
    renderApp(
      routes({
        'GET /api/remote-access': {
          body: {
            enabled: true,
            port: 8443,
            certificateSource: 'selfSigned',
            certificate: null,
            listening: false,
            lastError: 'address already in use',
          },
        },
      }),
    );
    expect(await screen.findByText('Last error: address already in use')).toBeInTheDocument();
    expect(screen.queryByText('Remote access on')).not.toBeInTheDocument();
  });

  it('links an error to the log page', async () => {
    renderApp(
      routes({
        'GET /api/connection': {
          body: makeStatus({
            state: 'error',
            profileId: 'p1',
            lastError: {
              code: 'auth_failed',
              message: 'AUTH_FAILED',
              time: '2026-11-25T10:00:00Z',
            },
          }),
        },
        'GET /api/logs?tail=2000': { body: { lines: [] } },
      }),
    );
    fireEvent.click(await screen.findByRole('link', { name: 'Open log for details' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Log' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/log');
  });

  it('connects the chosen profile', async () => {
    const { fetchMock } = renderApp(
      routes({
        'POST /api/connection/connect': {
          status: 202,
          body: makeStatus({ state: 'connecting', profileId: 'p1', profileName: 'Office' }),
        },
      }),
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Connect' }));

    expect((await screen.findAllByText('Connecting')).length).toBeGreaterThan(0);
    const call = fetchMock.mock.calls.find(([url]) => url === '/api/connection/connect');
    expect(call?.[1]?.body).toBe(JSON.stringify({ profileId: 'p1' }));
  });

  it('applies state, traffic and log events from the stream', async () => {
    const { queryClient } = renderApp(
      routes({
        'GET /api/connection': [
          { body: makeStatus() },
          {
            body: makeStatus({
              state: 'connected',
              profileId: 'p1',
              profileName: 'Office',
              vpnIp: '10.8.0.6',
              remote: '203.0.113.7:1194',
            }),
          },
        ],
      }),
    );
    await screen.findByRole('region', { name: 'Connection details' });
    const source = FakeEventSource.latest();

    act(() => {
      source.open();
      source.emit('state', {
        state: 'connected',
        vpnIp: '10.8.0.6',
        remote: '203.0.113.7:1194',
        since: new Date().toISOString(),
      });
    });
    expect((await screen.findAllByText('Connected')).length).toBeGreaterThan(0);
    expect(await screen.findAllByText('10.8.0.6')).toHaveLength(2);
    // Let the refetch triggered by the state event settle first.
    await waitFor(() => expect(queryClient.isFetching()).toBe(0));

    act(() => {
      source.emit('traffic', { bytesIn: 2_500_000, bytesOut: 1000, rateIn: 125_000, rateOut: 0 });
    });
    const details = screen.getByRole('region', { name: 'Connection details' });
    expect(await within(details).findByText('Received 2.5 MB')).toBeInTheDocument();
    expect(screen.getByText('→ Received: 1.0 Mbit/s')).toBeInTheDocument();
  });

  it('applies channel events to the encryption row', async () => {
    renderApp(
      routes({
        'GET /api/connection': {
          body: makeStatus({ state: 'connected', profileId: 'p1', profileName: 'Office' }),
        },
      }),
    );
    await screen.findByRole('region', { name: 'Connection details' });
    const source = FakeEventSource.latest();
    act(() => {
      source.open();
      source.emit('channel', { dataCipher: 'AES-256-GCM' });
    });
    const details = screen.getByRole('region', { name: 'Connection details' });
    expect(await within(details).findByText(/Data channel AES-256-GCM/)).toBeInTheDocument();

    act(() => {
      source.emit('channel', { controlChannel: 'TLSv1.3 TLS_AES_256_GCM_SHA384' });
    });
    expect(
      await within(details).findByText(/Control channel TLSv1.3 TLS_AES_256_GCM_SHA384/),
    ).toBeInTheDocument();
    expect(within(details).getByText(/Data channel AES-256-GCM/)).toBeInTheDocument();
  });

  it('reconnects the stream with backoff after it ends', async () => {
    renderApp(routes());
    await screen.findByRole('region', { name: 'Connection details' });
    vi.useFakeTimers();
    const first = FakeEventSource.latest();

    act(() => first.fail());
    expect(first.readyState).toBe(2);
    expect(FakeEventSource.instances).toHaveLength(1);

    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(FakeEventSource.instances).toHaveLength(2);
  });

  it('returns to sign-in when the stream fails because the session expired', async () => {
    renderApp(
      routes({
        'GET /api/connection': [{ body: makeStatus() }, problem(401, 'unauthenticated', 'expired')],
      }),
    );
    await screen.findByRole('region', { name: 'Connection details' });

    act(() => FakeEventSource.latest().fail());

    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument();
  });
});
