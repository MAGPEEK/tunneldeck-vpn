import { fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { AuditEntry, AuditPage } from '../../api/audit';
import type { MockRoutes } from '../../test/fetchMock';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const SYSTEM = {
  version: '1.2.3',
  listenAddress: '192.168.1.2:8194',
  serverTime: '2026-11-27T10:00:00Z',
  timeZone: 'Europe/Berlin',
  checks: [],
};

function entry(overrides: Partial<AuditEntry>): AuditEntry {
  return {
    id: 1,
    time: '2026-11-27T09:00:00Z',
    type: 'signedIn',
    severity: 'info',
    clientIp: '192.168.1.20',
    access: 'lan',
    count: 1,
    ...overrides,
  };
}

const PAGE: AuditPage = {
  entries: [
    entry({
      id: 3,
      time: '2026-11-27T09:30:00Z',
      type: 'csrfRejected',
      severity: 'warning',
      clientIp: '203.0.113.9',
      access: 'remote',
      count: 4,
    }),
    entry({ id: 2, type: 'wrongCredentials', severity: 'notice' }),
    entry({ id: 1, username: 'admin' }),
  ],
  hasMore: false,
  recentWarnings: 0,
};

function routes(page: AuditPage, extra: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/system': { body: SYSTEM },
    'GET /api/remote-access': {
      body: { enabled: false, port: 8443, certificateSource: 'selfSigned', listening: false },
    },
    'GET /api/public-ip-lookup': { body: { enabled: true, url: 'https://api.ipify.org' } },
    'GET /api/logs?tail=2000': { body: { lines: [] } },
    'GET /api/audit?limit=50': { body: page },
    ...extra,
  };
}

async function auditCard(): Promise<HTMLElement> {
  // The title gains an attack count when there are recent warnings, so match a prefix.
  return (await screen.findByRole('heading', { name: /^Sign-ins/ })).closest(
    'section',
  ) as HTMLElement;
}

describe('AuditCard', () => {
  it('lists entries with zoned time, coloured event, IP and access', async () => {
    renderApp(routes(PAGE), '/log?tab=sign-ins');
    const card = await auditCard();
    const rows = await within(card).findAllByRole('row');
    expect(rows).toHaveLength(4);
    const first = within(rows[1] as HTMLElement);
    expect(first.getByText('Nov 27, 2026, 10:30:00 AM')).toBeInTheDocument();
    expect(first.getByText('Blocked: cross-site or scripted request (4×)')).toHaveAttribute(
      'data-tone',
      'danger',
    );
    expect(first.getByText('203.0.113.9')).toBeInTheDocument();
    expect(first.getByText('Remote')).toBeInTheDocument();
    expect(within(rows[2] as HTMLElement).getByText('Wrong username or password')).toHaveAttribute(
      'data-tone',
      'warning',
    );
    expect(within(rows[3] as HTMLElement).getByText('Signed in')).toHaveAttribute(
      'data-tone',
      'success',
    );
    expect(within(rows[3] as HTMLElement).getByText('LAN')).toBeInTheDocument();
    expect(within(card).queryByText(/blocked attempt/)).not.toBeInTheDocument();
  });

  it('highlights attack and failed rows and leaves successes plain', async () => {
    renderApp(routes(PAGE), '/log?tab=sign-ins');
    const card = await auditCard();
    const rows = await within(card).findAllByRole('row');
    // Warning-level security event: danger styling plus the attack tag.
    const attack = rows[1] as HTMLElement;
    expect(attack).toHaveAttribute('data-severity', 'attack');
    expect(within(attack).getByText('Attack')).toBeInTheDocument();
    // Notice-level failed sign-in: milder styling plus the failed tag.
    const failed = rows[2] as HTMLElement;
    expect(failed).toHaveAttribute('data-severity', 'failure');
    expect(within(failed).getByText('Failed')).toBeInTheDocument();
    // Successful sign-in: no severity marker.
    const success = rows[3] as HTMLElement;
    expect(success).not.toHaveAttribute('data-severity');
    expect(within(success).queryByText('Attack')).not.toBeInTheDocument();
    expect(within(success).queryByText('Failed')).not.toBeInTheDocument();
  });

  it('warns about blocked attempts of the last 24 hours and a sign-in from a new address', async () => {
    const newRemote = entry({ id: 9, clientIp: '10.8.0.6', access: 'remote' });
    renderApp(
      routes({ ...PAGE, recentWarnings: 12, newRemoteSignIn: newRemote }),
      '/log?tab=sign-ins',
    );
    const card = await auditCard();
    expect(
      await within(card).findByRole('heading', { name: 'Sign-ins · 12 attacks' }),
    ).toBeInTheDocument();
    expect(
      await within(card).findByText('12 blocked attempts in the last 24 hours'),
    ).toBeInTheDocument();
    expect(within(card).getByText('Sign-in from a new address')).toBeInTheDocument();
    expect(
      within(card).getByText(
        /came over remote access from 10\.8\.0\.6 \(Nov 27, 2026, 10:00:00 AM\)/,
      ),
    ).toBeInTheDocument();
  });

  it('filters failures and security events on the server', async () => {
    const failures: AuditPage = { ...PAGE, entries: [PAGE.entries[1] as AuditEntry] };
    const security: AuditPage = { ...PAGE, entries: [PAGE.entries[0] as AuditEntry] };
    const { fetchMock } = renderApp(
      routes(PAGE, {
        'GET /api/audit?limit=50&filter=failures': { body: failures },
        'GET /api/audit?limit=50&filter=security': { body: security },
      }),
      '/log?tab=sign-ins',
    );
    const card = await auditCard();
    await within(card).findByText('Signed in');
    fireEvent.click(within(card).getByRole('radio', { name: 'Only failed sign-ins' }));
    expect(await within(card).findAllByRole('row')).toHaveLength(2);
    expect(within(card).getByText('Wrong username or password')).toBeInTheDocument();
    fireEvent.click(within(card).getByRole('radio', { name: 'Only security events' }));
    expect(
      await within(card).findByText('Blocked: cross-site or scripted request (4×)'),
    ).toBeInTheDocument();
    expect(within(card).queryByText('Wrong username or password')).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/audit?limit=50&filter=security',
      expect.anything(),
    );
  });

  it('loads older entries below the last one', async () => {
    const older: AuditPage = {
      entries: [entry({ id: 1, type: 'signedOut' })],
      hasMore: false,
      recentWarnings: 0,
    };
    renderApp(
      routes(
        { ...PAGE, entries: PAGE.entries.slice(0, 2), hasMore: true },
        { 'GET /api/audit?limit=50&before=2': { body: older } },
      ),
      '/log?tab=sign-ins',
    );
    const card = await auditCard();
    fireEvent.click(await within(card).findByRole('button', { name: 'Show older entries' }));
    expect(await within(card).findByText('Signed out')).toBeInTheDocument();
    expect(within(card).getAllByRole('row')).toHaveLength(4);
    expect(
      within(card).queryByRole('button', { name: 'Show older entries' }),
    ).not.toBeInTheDocument();
  });

  it('shows an empty log', async () => {
    renderApp(routes({ entries: [], hasMore: false, recentWarnings: 0 }), '/log?tab=sign-ins');
    const card = await auditCard();
    expect(await within(card).findByText('No entries yet.')).toBeInTheDocument();
  });
});
