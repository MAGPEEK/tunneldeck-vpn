import type { Advisory } from '../../../api/profiles';
import { fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { problem, type MockRoutes } from '../../../test/fetchMock';
import { DRIVERS, makeProfile, makeStatus } from '../../../test/fixtures';
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
        keyDirection: '1',
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
});

describe('edit profile', () => {
  const profile = makeProfile({ advisories: mdexAdvisories });

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
