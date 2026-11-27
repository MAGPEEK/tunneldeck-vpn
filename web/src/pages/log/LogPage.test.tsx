import { act, fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { MockRoutes } from '../../test/fetchMock';
import { FakeEventSource } from '../../test/fakeEventSource';
import { makeStatus } from '../../test/fixtures';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const SYSTEM = {
  version: '1.2.3',
  listenAddress: '192.168.1.2:8194',
  serverTime: '2026-11-27T10:00:00Z',
  timeZone: 'Europe/Berlin',
  checks: [],
};

const AUDIT = {
  entries: [
    {
      id: 1,
      time: '2026-11-27T09:00:00Z',
      type: 'signedIn',
      severity: 'info',
      clientIp: '192.168.1.20',
      access: 'lan',
      count: 1,
    },
  ],
  hasMore: false,
  recentWarnings: 0,
};

function routes(overrides: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/connection': { body: makeStatus() },
    'GET /api/logs?tail=2000': {
      body: {
        lines: [{ time: '2026-11-25T10:00:00Z', level: 'info', text: 'TunnelDeck started' }],
      },
    },
    'GET /api/system': { body: SYSTEM },
    'GET /api/audit?limit=50': { body: AUDIT },
    ...overrides,
  };
}

describe('LogPage', () => {
  it('shows the stored lines and appends lines from the event stream on the VPN tab', async () => {
    renderApp(routes(), '/log');

    expect(await screen.findByRole('heading', { level: 1, name: 'Log' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'VPN log', selected: true })).toBeInTheDocument();
    expect(await screen.findByText('TunnelDeck started')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Level' })).toBeInTheDocument();

    act(() => {
      FakeEventSource.latest().emit('log', {
        time: '2026-11-25T10:00:05Z',
        level: 'error',
        text: 'Something broke',
      });
    });
    expect(await screen.findByText('Something broke')).toBeInTheDocument();
  });

  it('switches to the sign-ins tab, shows the audit table and reflects the tab in the URL', async () => {
    renderApp(routes(), '/log');
    await screen.findByText('TunnelDeck started');

    fireEvent.click(screen.getByRole('tab', { name: 'Sign-ins' }));

    const heading = await screen.findByRole('heading', { name: /^Sign-ins/ });
    const card = heading.closest('section') as HTMLElement;
    expect(await within(card).findByText('Signed in')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Sign-ins', selected: true })).toBeInTheDocument();
    expect(screen.queryByText('TunnelDeck started')).not.toBeInTheDocument();
    expect(window.location.search).toBe('?tab=sign-ins');
  });

  it('opens the sign-ins tab directly from the URL', async () => {
    renderApp(routes(), '/log?tab=sign-ins');

    expect(await screen.findByRole('heading', { name: /^Sign-ins/ })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Sign-ins', selected: true })).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Level' })).not.toBeInTheDocument();
  });

  it('points the help link at the section of the active tab', async () => {
    renderApp(routes(), '/log');
    expect(await screen.findByRole('link', { name: 'Help for this page' })).toHaveAttribute(
      'href',
      '/help#troubleshooting',
    );

    fireEvent.click(screen.getByRole('tab', { name: 'Sign-ins' }));
    expect(await screen.findByRole('link', { name: 'Help for this page' })).toHaveAttribute(
      'href',
      '/help#sign-ins',
    );
  });
});
