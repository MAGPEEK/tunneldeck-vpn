import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FakeEventSource } from '../../test/fakeEventSource';
import { problem, type MockRoutes } from '../../test/fetchMock';
import { makeProfile, makeStatus } from '../../test/fixtures';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const profile = makeProfile();

function routes(overrides: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/profiles': { body: [profile] },
    'GET /api/connection': { body: makeStatus() },
    'GET /api/host-access': {
      body: {
        rules: [
          { id: 'a', protocol: 'tcp', port: 5001, sourceCidr: '', enabled: true, comment: 'DSM' },
          { id: 'b', protocol: 'udp', port: 53, sourceCidr: '', enabled: false, comment: '' },
        ],
      },
    },
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
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
    expect(window.location.pathname).toBe('/profiles/new');
  });

  it('shows the connection, metrics, host protection and log', async () => {
    renderApp(routes());

    expect(await screen.findByRole('heading', { name: 'Office' })).toBeInTheDocument();
    expect(screen.getByText('Disconnected')).toBeInTheDocument();
    expect(within(screen.getByLabelText('Traffic')).getAllByText('–')).toHaveLength(4);
    expect(screen.getByText('1 port open: TCP 5001')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Manage host access' })).toHaveAttribute(
      'href',
      '/host-access',
    );
    expect(await screen.findByText('TunnelDeck started')).toBeInTheDocument();
    expect(FakeEventSource.latest().url).toBe('/api/events');
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
