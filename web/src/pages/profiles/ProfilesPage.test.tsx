import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { problem, type MockRoutes } from '../../test/fetchMock';
import { DRIVERS, makeProfile, makeStatus } from '../../test/fixtures';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const office = makeProfile({ dailyReconnect: { enabled: true, time: '04:30' } });
const mdex = makeProfile({
  id: 'p2',
  name: 'mdex',
  settings: { remoteHost: 'publicip20.mdex.de', port: 1194, authMode: 'password' },
});

function routes(overrides: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/profiles': { body: [office, mdex] },
    'GET /api/connection': {
      body: makeStatus({ state: 'connected', profileId: 'p2', profileName: 'mdex' }),
    },
    'GET /api/drivers': { body: DRIVERS },
    'GET /api/system': {
      body: {
        version: '1.0.0',
        listenAddress: '192.168.1.2:8194',
        serverTime: '2026-11-25T10:00:00Z',
        timeZone: 'Europe/Berlin',
        checks: [],
      },
    },
    ...overrides,
  };
}

function row(name: string): HTMLElement {
  const cell = screen.getByRole('cell', { name });
  const tr = cell.closest('tr');
  if (!tr) throw new Error(`no row for ${name}`);
  return tr;
}

describe('ProfilesPage', () => {
  it('lists profiles with protocol, server, daily reconnect and the active marker', async () => {
    renderApp(routes(), '/profiles');
    await screen.findByRole('cell', { name: 'Office' });

    expect(within(row('Office')).getByText('vpn.example.com:1194')).toBeInTheDocument();
    expect(within(row('Office')).getByText('04:30')).toBeInTheDocument();
    expect(within(row('Office')).getByText('OpenVPN')).toBeInTheDocument();
    expect(within(row('mdex')).getByText('Off')).toBeInTheDocument();
    expect(within(row('mdex')).getByText('Active')).toBeInTheDocument();
    expect(within(row('Office')).queryByText('Active')).not.toBeInTheDocument();
  });

  it('disables delete with a hint while the profile is connected', async () => {
    renderApp(routes(), '/profiles');
    const button = await screen.findByRole('button', { name: 'Delete mdex' });
    expect(button).toBeDisabled();
    expect(button).toHaveAccessibleDescription('Disconnect to delete');
    expect(screen.getByRole('button', { name: 'Delete Office' })).toBeEnabled();
  });

  it('deletes after an inline confirmation', async () => {
    const { fetchMock } = renderApp(
      routes({
        'GET /api/profiles': [{ body: [office, mdex] }, { body: [mdex] }],
        'DELETE /api/profiles/p1': { status: 204 },
      }),
      '/profiles',
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Office' }));
    const confirm = screen.getByRole('group', { name: 'Confirm deletion' });
    expect(confirm).toHaveTextContent('Delete the profile "Office"?');

    fireEvent.click(within(confirm).getByRole('button', { name: 'Delete profile' }));

    await waitFor(() =>
      expect(screen.queryByRole('cell', { name: 'Office' })).not.toBeInTheDocument(),
    );
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/profiles/p1',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });

  it('cancels the confirmation without deleting', async () => {
    const { fetchMock } = renderApp(routes(), '/profiles');
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Office' }));
    fireEvent.click(
      within(screen.getByRole('group', { name: 'Confirm deletion' })).getByRole('button', {
        name: 'Cancel',
      }),
    );
    expect(screen.queryByRole('group', { name: 'Confirm deletion' })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
  });

  it('shows a refused delete', async () => {
    renderApp(
      routes({
        'DELETE /api/profiles/p1': problem(
          409,
          'conflict',
          'Disconnect the profile before deleting it.',
        ),
      }),
      '/profiles',
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Office' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete profile' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be deleted');
  });

  it('opens the edit form', async () => {
    renderApp(routes({ 'GET /api/profiles/p1': { body: office } }), '/profiles');
    fireEvent.click(await screen.findByRole('button', { name: 'Edit Office' }));
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Edit profile' }),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe('/profiles/p1');
    expect(await screen.findByLabelText('Name')).toHaveValue('Office');
  });

  it('duplicates a profile into the new form without its secrets', async () => {
    renderApp(routes({ 'GET /api/profiles/p1': { body: office } }), '/profiles');
    fireEvent.click(await screen.findByRole('button', { name: 'Duplicate Office' }));

    expect(await screen.findByLabelText('Name')).toHaveValue('Office (copy)');
    expect(window.location.pathname).toBe('/profiles/new');
    expect(screen.getByLabelText('Server address')).toHaveValue('vpn.example.com');
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(
      screen.getByText(/Secrets such as passwords and keys are not copied/),
    ).toBeInTheDocument();
  });
});

describe('import', () => {
  const draft = {
    settings: {
      remoteHost: 'publicip20.mdex.de',
      port: 1194,
      proto: 'udp',
      authMode: 'password',
      cipher: 'none',
      extraOptions: ['tun-mtu 1500', 'float'],
    },
    secrets: { tlsAuthKey: '-----BEGIN OpenVPN Static key V1-----' },
    warnings: [
      {
        code: 'runs_code',
        severity: 'rejected',
        directive: 'up',
        line: 12,
        message: 'runs a script',
      },
      {
        code: 'routing_handled',
        severity: 'warning',
        directive: 'redirect-gateway',
        line: 7,
        message: 'handled by TunnelDeck',
      },
      { code: 'cipher_mapped', severity: 'info', directive: 'cipher', message: 'mapped' },
    ],
  };

  it('sends the pasted text and opens the pre-filled form with grouped warnings', async () => {
    const { fetchMock } = renderApp(
      routes({ 'POST /api/profiles/import': { body: draft } }),
      '/profiles',
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Import .ovpn' }));
    fireEvent.change(screen.getByLabelText('Or paste the configuration'), {
      target: { value: 'client\nremote publicip20.mdex.de 1194' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));

    expect(
      await screen.findByRole('heading', { level: 1, name: 'New profile' }),
    ).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(([url]) => url === '/api/profiles/import');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      protocol: 'openvpn',
      text: 'client\nremote publicip20.mdex.de 1194',
    });

    expect(await screen.findByLabelText('Server address')).toHaveValue('publicip20.mdex.de');
    expect(screen.getByLabelText('Data channel cipher')).toHaveValue('none');
    expect(screen.getByLabelText('TLS auth key')).toHaveValue(
      '-----BEGIN OpenVPN Static key V1-----',
    );
    expect(screen.getByRole('textbox', { name: 'Extra options, line 2' })).toHaveValue('float');

    const rejected = screen
      .getByText('1 directive not imported')
      .closest('[data-tone]') as HTMLElement;
    expect(rejected).toHaveAttribute('data-tone', 'danger');
    expect(rejected).toHaveTextContent('Line 12: up Not imported: runs programs or scripts');
    expect(
      screen.getByText('1 directive dropped or changed').closest('[data-tone]'),
    ).toHaveAttribute('data-tone', 'warning');
    expect(screen.getByText('1 note')).toBeInTheDocument();
  });

  it('shows a file problem under the text field', async () => {
    renderApp(
      routes({
        'POST /api/profiles/import': problem(422, 'validation_failed', 'invalid', {
          fields: { file: 'must be at most 1 MiB' },
        }),
      }),
      '/profiles',
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Import .ovpn' }));
    fireEvent.change(screen.getByLabelText('Or paste the configuration'), {
      target: { value: 'x' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    expect(await screen.findByText('must be at most 1 MiB')).toBeInTheDocument();
  });
});
