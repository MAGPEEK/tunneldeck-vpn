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
    'GET /api/logs?tail=2000': {
      body: {
        lines: [{ time: '2026-11-25T10:00:00Z', level: 'info', text: 'TunnelDeck started' }],
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

  it('shows the connection, metrics, host protection and log', async () => {
    renderApp(routes());

    expect(await screen.findByRole('heading', { name: 'Office' })).toBeInTheDocument();
    expect(screen.getByText('Disconnected')).toBeInTheDocument();
    expect(within(screen.getByLabelText('Traffic')).getAllByText('–')).toHaveLength(4);
    expect(await screen.findByText('1 inbound rule, 0 outbound rules')).toBeInTheDocument();
    expect(screen.queryByText(/IP forwarding is off/)).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Manage firewall' })).toHaveAttribute(
      'href',
      '/firewall',
    );
    expect(await screen.findByText('TunnelDeck started')).toBeInTheDocument();
    expect(FakeEventSource.latest().url).toBe('/api/events');
  });

  it('warns when IP forwarding is off and a rule needs it', async () => {
    renderApp(
      routes({
        'GET /api/firewall': { body: firewall({ rules: [adminUi, routerOut], ipForward: false }) },
      }),
    );
    expect(await screen.findByText('1 inbound rule, 1 outbound rule')).toBeInTheDocument();
    expect(
      screen.getByText(
        'IP forwarding is off on the host: port forwards and outbound rules do not work.',
      ),
    ).toBeInTheDocument();
  });

  it('does not warn about IP forwarding when only rules to this device exist', async () => {
    renderApp(routes({ 'GET /api/firewall': { body: firewall({ ipForward: false }) } }));
    expect(await screen.findByText('1 inbound rule, 0 outbound rules')).toBeInTheDocument();
    expect(screen.queryByText(/IP forwarding is off/)).not.toBeInTheDocument();
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

    expect(await screen.findByText('Connecting')).toBeInTheDocument();
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
    await screen.findByText('Disconnected');
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
    expect(await screen.findByText('Connected')).toBeInTheDocument();
    expect(await screen.findByText('10.8.0.6')).toBeInTheDocument();
    // Let the refetch triggered by the state event settle first.
    await waitFor(() => expect(queryClient.isFetching()).toBe(0));

    act(() => {
      source.emit('traffic', { bytesIn: 2_500_000, bytesOut: 1000, rateIn: 125_000, rateOut: 0 });
      source.emit('log', { time: '2026-11-25T10:00:05Z', level: 'error', text: 'Something broke' });
    });
    const traffic = screen.getByLabelText('Traffic');
    expect(await within(traffic).findByText('2.5 MB')).toBeInTheDocument();
    expect(within(traffic).getByText('1.0 Mbit/s')).toBeInTheDocument();
    expect(await screen.findByText('Something broke')).toBeInTheDocument();
  });

  it('reconnects the stream with backoff after it ends', async () => {
    renderApp(routes());
    await screen.findByText('Disconnected');
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
    await screen.findByText('Disconnected');

    act(() => FakeEventSource.latest().fail());

    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument();
  });
});
