import { fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { problem, type MockRoutes } from '../../test/fetchMock';
import { makeProfile, makeStatus } from '../../test/fixtures';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const SYSTEM = {
  version: '1.2.3',
  listenAddress: '192.168.1.2:8194',
  serverTime: '2026-11-25T10:00:00Z',
  timeZone: 'Europe/Berlin',
  checks: [
    { id: 'tun-device', ok: true, detail: '/dev/net/tun is present' },
    {
      id: 'iptables',
      ok: false,
      detail: 'iptables not found',
      hint: 'Install iptables in the image.',
    },
  ],
};

const REMOTE = {
  enabled: false,
  port: 8443,
  certificateSource: 'selfSigned',
  certificate: {
    subject: 'CN=TunnelDeck',
    notBefore: '2026-11-01T00:00:00Z',
    notAfter: '2028-11-01T00:00:00Z',
    fingerprintSha256: 'AB:CD:EF',
    selfSigned: true,
  },
  listening: false,
};

function routes(overrides: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/system': { body: SYSTEM },
    'GET /api/remote-access': { body: REMOTE },
    ...overrides,
  };
}

async function remoteCard(): Promise<HTMLElement> {
  return (await screen.findByRole('heading', { name: 'Remote access' })).closest(
    'section',
  ) as HTMLElement;
}

describe('SystemPage', () => {
  it('shows version, listen address, server time and the self-check with hints', async () => {
    renderApp(routes(), '/system');
    expect(await screen.findByText('1.2.3')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.2:8194')).toBeInTheDocument();
    expect(screen.getByText('(Europe/Berlin)')).toBeInTheDocument();
    expect(screen.getByText('TUN device')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Passed' })).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Failed' })).toBeInTheDocument();
    expect(screen.getByText(/Install iptables in the image and make sure/)).toBeInTheDocument();
  });

  it('labels the IP forwarding and LAN checks and translates their hints', async () => {
    renderApp(
      routes({
        'GET /api/system': {
          body: {
            ...SYSTEM,
            checks: [
              { id: 'ip-forward', ok: false, detail: 'net.ipv4.ip_forward is 0', hint: 'x' },
              { id: 'lan-subnets', ok: true, detail: '192.168.1.0/24' },
            ],
          },
        },
      }),
      '/system',
    );
    expect(await screen.findByText('IP forwarding')).toBeInTheDocument();
    expect(screen.getByText('LAN subnets')).toBeInTheDocument();
    expect(screen.getByText(/Enable IPv4 forwarding on the host/)).toBeInTheDocument();
  });

  it('shows a warning check with a warning icon instead of a failure', async () => {
    renderApp(
      routes({
        'GET /api/system': {
          body: {
            ...SYSTEM,
            checks: [
              {
                id: 'rule-counters',
                ok: false,
                warning: true,
                detail: 'the iptables comment match is unavailable',
                hint: 'x',
              },
            ],
          },
        },
      }),
      '/system',
    );
    expect(await screen.findByRole('img', { name: 'Warning' })).toBeInTheDocument();
    expect(screen.queryByRole('img', { name: 'Failed' })).not.toBeInTheDocument();
    expect(screen.getByText(/Load the comment match on the host/)).toBeInTheDocument();
  });

  it('translates each check detail by its code and shows hints only for failures', async () => {
    renderApp(
      routes({
        'GET /api/system': {
          body: {
            ...SYSTEM,
            checks: [
              {
                id: 'tun-device',
                ok: true,
                detailCode: 'tunPresent',
                params: { path: '/dev/net/tun' },
                detail: '/dev/net/tun is present',
              },
              {
                id: 'syn-flood-protection',
                ok: false,
                warning: true,
                detailCode: 'synFloodGlobal',
                params: { module: 'xt_hashlimit', fallback: 'limit' },
                detail: 'English fallback',
                hint: 'x',
              },
              {
                id: 'ip',
                ok: false,
                detailCode: 'somethingNew',
                detail: 'server detail for an unknown code',
                hint: 'x',
              },
            ],
          },
        },
      }),
      '/system',
    );
    const tun = (await screen.findByText('TUN device')).closest('li') as HTMLElement;
    expect(within(tun).getByText('/dev/net/tun is present.')).toBeInTheDocument();
    expect(within(tun).getAllByRole('paragraph')).toHaveLength(1);

    const syn = screen.getByText('SYN flood protection').closest('li') as HTMLElement;
    expect(
      within(syn).getByText(
        /xt_hashlimit\) is unavailable, so the protection falls back to the limit match/,
      ),
    ).toBeInTheDocument();
    expect(within(syn).queryByText('English fallback')).not.toBeInTheDocument();
    expect(within(syn).getByText(/Load the hashlimit match on the host/)).toBeInTheDocument();
    expect(within(syn).getAllByRole('paragraph')).toHaveLength(2);

    const ip = screen.getByText('ip tool').closest('li') as HTMLElement;
    expect(within(ip).getByText('server detail for an unknown code')).toBeInTheDocument();
  });

  it('shows how long the container has been running, and no host uptime', async () => {
    const now = Date.now();
    renderApp(
      routes({
        'GET /api/system': {
          body: {
            ...SYSTEM,
            serverTime: new Date(now).toISOString(),
            startedAt: new Date(now - ((5 * 24 + 4) * 3600 + 12 * 60 + 30) * 1000).toISOString(),
          },
        },
      }),
      '/system',
    );
    const process = (await screen.findByText('Container running for')).nextElementSibling;
    expect(process).toHaveTextContent('5 days 4 h 12 min');
    expect(process?.querySelector('time')).toHaveAttribute(
      'title',
      expect.stringMatching(/^Started /),
    );
    expect(screen.queryByText('Host running for')).not.toBeInTheDocument();
  });

  it('shows the remote access URL at the public address of the connected profile', async () => {
    renderApp(
      routes({
        'GET /api/remote-access': { body: { ...REMOTE, enabled: true, listening: true } },
        'GET /api/connection': {
          body: makeStatus({ state: 'connected', profileId: 'p1', vpnIp: '172.21.31.170' }),
        },
        'GET /api/profiles': { body: [makeProfile({ publicAddress: 'vpn.example.com' })] },
      }),
      '/system',
    );
    const card = await remoteCard();
    expect(
      await within(card).findByRole('link', { name: 'https://vpn.example.com:8443' }),
    ).toHaveAttribute('href', 'https://vpn.example.com:8443');
    expect(within(card).queryByRole('link', { name: 'Edit profile' })).not.toBeInTheDocument();
  });

  it('falls back to the VPN IP and links the profile where the public address is set', async () => {
    renderApp(
      routes({
        'GET /api/remote-access': { body: { ...REMOTE, enabled: true, listening: true } },
        'GET /api/connection': {
          body: makeStatus({ state: 'connected', profileId: 'p1', vpnIp: '172.21.31.170' }),
        },
        'GET /api/profiles': { body: [makeProfile()] },
      }),
      '/system',
    );
    const card = await remoteCard();
    expect(
      await within(card).findByRole('link', { name: 'https://172.21.31.170:8443' }),
    ).toBeInTheDocument();
    expect(within(card).getByRole('link', { name: 'Edit profile' })).toHaveAttribute(
      'href',
      '/profiles/p1',
    );
  });

  it('shows a neutral note when this build has no remote access', async () => {
    renderApp(
      routes({
        'GET /api/remote-access': problem(404, 'not_found', 'The resource does not exist.'),
      }),
      '/system',
    );
    const card = await remoteCard();
    expect(await within(card).findByText('Not available in this build.')).toBeInTheDocument();
    expect(within(card).queryByRole('alert')).not.toBeInTheDocument();
  });

  it('warns, shows the certificate and copies its fingerprint', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    renderApp(routes(), '/system');
    const card = await remoteCard();

    expect(
      await within(card).findByText('The sign-in page becomes reachable from the internet.'),
    ).toBeInTheDocument();
    expect(within(card).getByText('Remote access is off.')).toBeInTheDocument();
    expect(within(card).getByText('CN=TunnelDeck')).toBeInTheDocument();
    fireEvent.click(within(card).getByRole('button', { name: 'Copy' }));
    expect(await within(card).findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith('AB:CD:EF');
  });

  it('saves enable, port and certificate source', async () => {
    const { fetchMock } = renderApp(
      routes({
        'PUT /api/remote-access': {
          body: { ...REMOTE, enabled: true, port: 9443, listening: true },
        },
      }),
      '/system',
    );
    const card = await remoteCard();
    const save = await within(card).findByRole('button', { name: 'Save changes' });
    expect(save).toBeDisabled();

    fireEvent.click(
      within(card).getByRole('checkbox', { name: 'Enable remote access over HTTPS' }),
    );
    fireEvent.change(within(card).getByLabelText('HTTPS port'), { target: { value: '9443' } });
    fireEvent.click(save);

    expect(await within(card).findByText('Listening on port 9443.')).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      enabled: true,
      port: 9443,
      certificateSource: 'selfSigned',
    });
  });

  it('shows field errors of a refused save', async () => {
    renderApp(
      routes({
        'PUT /api/remote-access': problem(422, 'validation_failed', 'invalid', {
          fields: { port: 'must not be the HTTP port' },
        }),
      }),
      '/system',
    );
    const card = await remoteCard();
    fireEvent.change(await within(card).findByLabelText('HTTPS port'), {
      target: { value: '8194' },
    });
    fireEvent.click(within(card).getByRole('button', { name: 'Save changes' }));
    expect(await within(card).findByText('must not be the HTTP port')).toBeInTheDocument();
  });

  it('uploads a certificate when the source is uploaded', async () => {
    const { fetchMock } = renderApp(
      routes({
        'POST /api/remote-access/certificate': {
          body: {
            ...REMOTE,
            certificateSource: 'uploaded',
            certificate: {
              ...REMOTE.certificate,
              subject: 'CN=nas.example.com',
              selfSigned: false,
            },
          },
        },
      }),
      '/system',
    );
    const card = await remoteCard();
    fireEvent.click(await within(card).findByRole('radio', { name: 'Uploaded' }));
    fireEvent.change(within(card).getByLabelText('Certificate chain (PEM)'), {
      target: { value: 'CERT' },
    });
    fireEvent.change(within(card).getByLabelText('Private key (PEM)'), {
      target: { value: 'KEY' },
    });
    fireEvent.click(within(card).getByRole('button', { name: 'Upload certificate' }));

    expect(await within(card).findByText('CN=nas.example.com')).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(([url]) => url === '/api/remote-access/certificate');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ certificatePem: 'CERT', keyPem: 'KEY' });
  });

  it('shows the last listener error', async () => {
    renderApp(
      routes({
        'GET /api/remote-access': {
          body: { ...REMOTE, enabled: true, lastError: 'address in use' },
        },
      }),
      '/system',
    );
    const card = await remoteCard();
    expect(await within(card).findByText('Last error: address in use')).toBeInTheDocument();
  });

  describe('sign out everywhere', () => {
    async function sessionsCard(): Promise<HTMLElement> {
      return (await screen.findByRole('heading', { name: 'Sign-in sessions' })).closest(
        'section',
      ) as HTMLElement;
    }

    it('asks inline and can be cancelled', async () => {
      const { fetchMock } = renderApp(routes(), '/system');
      const card = await sessionsCard();
      fireEvent.click(within(card).getByRole('button', { name: 'Sign out everywhere' }));
      const confirm = within(card).getByRole('group', { name: 'Confirm sign out everywhere' });
      expect(confirm).toHaveTextContent('Sign out every browser now?');
      fireEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }));
      expect(within(card).queryByRole('group')).not.toBeInTheDocument();
      expect(fetchMock.mock.calls.some(([url]) => url === '/api/sessions')).toBe(false);
    });

    it('ends every session and shows the sign-in page', async () => {
      const { fetchMock } = renderApp(
        routes({ 'DELETE /api/sessions': { status: 204 } }),
        '/system',
      );
      const card = await sessionsCard();
      fireEvent.click(within(card).getByRole('button', { name: 'Sign out everywhere' }));
      const confirm = within(card).getByRole('group', { name: 'Confirm sign out everywhere' });
      fireEvent.click(within(confirm).getByRole('button', { name: 'Sign out everywhere' }));
      expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
      expect(
        fetchMock.mock.calls.some(
          ([url, init]) => url === '/api/sessions' && init?.method === 'DELETE',
        ),
      ).toBe(true);
    });

    it('shows an error when the server fails', async () => {
      renderApp(
        routes({ 'DELETE /api/sessions': problem(500, 'internal', 'An internal error occurred.') }),
        '/system',
      );
      const card = await sessionsCard();
      fireEvent.click(within(card).getByRole('button', { name: 'Sign out everywhere' }));
      const confirm = within(card).getByRole('group', { name: 'Confirm sign out everywhere' });
      fireEvent.click(within(confirm).getByRole('button', { name: 'Sign out everywhere' }));
      expect(await within(card).findByRole('alert')).toBeInTheDocument();
    });
  });
});
