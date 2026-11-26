import { fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { problem, type MockRoutes } from '../../test/fetchMock';
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
});
