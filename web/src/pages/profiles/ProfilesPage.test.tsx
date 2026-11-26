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
    missing: [],
  };

  /** A file-based provider profile: credentials and CA are not in the file. */
  const providerDraft = {
    settings: { remoteHost: '203.0.113.10', port: 1194, authMode: 'password' },
    secrets: {},
    warnings: [
      {
        code: 'file_reference',
        severity: 'rejected',
        directive: 'ca',
        line: 9,
        file: 'ca.crt',
        message: 'references the file',
      },
    ],
    missing: ['username', 'password', 'caCert'],
  };

  function ovpnFile(name = 'Provider VPN.ovpn', text = 'client\nremote 203.0.113.10\nca ca.crt') {
    return new File([text], name);
  }

  function chooseFile(file: File) {
    fireEvent.change(screen.getByTestId('profile-file-input'), { target: { files: [file] } });
  }

  function dragEvent(file: File) {
    return { dataTransfer: { types: ['Files'], files: [file], dropEffect: 'none' } };
  }

  it('makes loading a file the first, primary action', async () => {
    renderApp(routes(), '/profiles');
    await screen.findByRole('cell', { name: 'Office' });
    const load = screen.getByRole('button', { name: 'Load .ovpn file' });
    const paste = screen.getByRole('button', { name: 'Paste configuration' });
    const create = screen.getByRole('button', { name: 'New profile' });
    expect(load.compareDocumentPosition(paste) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(paste.compareDocumentPosition(create) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByTestId('profile-file-input')).toHaveAttribute('accept', '.ovpn,.conf');
  });

  it('sends the pasted text and opens the pre-filled form with grouped warnings', async () => {
    const { fetchMock } = renderApp(
      routes({ 'POST /api/profiles/import': { body: draft } }),
      '/profiles',
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Paste configuration' }));
    fireEvent.change(screen.getByLabelText('Configuration text'), {
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

    expect(await screen.findByLabelText('Name')).toHaveValue('publicip20.mdex.de');
    expect(screen.getByLabelText('Server address')).toHaveValue('publicip20.mdex.de');
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
    expect(screen.queryByText('Still missing from the file')).not.toBeInTheDocument();
  });

  it('shows a translated problem of the pasted text under the text field', async () => {
    renderApp(
      routes({
        'POST /api/profiles/import': problem(422, 'validation_failed', 'invalid', {
          fields: { file: 'is not an OpenVPN profile' },
          fieldCodes: { file: { code: 'openvpn_not_a_profile' } },
        }),
      }),
      '/profiles',
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Paste configuration' }));
    fireEvent.change(screen.getByLabelText('Configuration text'), {
      target: { value: 'hello' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    expect(
      await screen.findByText('This is not an OpenVPN profile: it contains no OpenVPN directive.'),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('Configuration text')).toHaveAttribute('aria-invalid', 'true');
  });

  it('loads a chosen file, names the profile after it and highlights only what is missing', async () => {
    const { fetchMock } = renderApp(
      routes({ 'POST /api/profiles/import': { body: providerDraft } }),
      '/profiles',
    );
    await screen.findByRole('cell', { name: 'Office' });
    chooseFile(ovpnFile());

    expect(await screen.findByLabelText('Name')).toHaveValue('Provider VPN');
    const call = fetchMock.mock.calls.find(([url]) => url === '/api/profiles/import');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      protocol: 'openvpn',
      text: 'client\nremote 203.0.113.10\nca ca.crt',
    });

    const summary = screen.getByText('Still missing from the file').closest('[data-tone]');
    expect(summary).toHaveTextContent('Username');
    expect(summary).toHaveTextContent('Password');
    expect(summary).toHaveTextContent('CA certificate');
    const hint = 'Not in the file – please enter.';
    expect(screen.getByLabelText('Username')).toHaveAccessibleDescription(hint);
    expect(screen.getByLabelText('CA certificate')).toHaveAccessibleDescription(hint);
    expect(screen.getByLabelText('Server address')).not.toHaveAttribute('aria-invalid');

    expect(
      screen.getByText(/refers to the file ca\.crt, which is not part of the profile/),
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'alice' } });
    expect(screen.getByLabelText('Username')).not.toHaveAttribute('aria-invalid');
    expect(summary).not.toHaveTextContent('Username');
  });

  it('loads the mdex fixed.IP level 30 file without alarming warnings and asks only for the credentials', async () => {
    const line = (code: string, severity: string, directive: string, at: number) => ({
      code,
      severity,
      directive,
      line: at,
      message: code,
    });
    const mdexDraft = {
      settings: {
        remoteHost: 'openvpn30.mdex.de',
        port: 1194,
        proto: 'udp',
        authMode: 'password',
        caCert: '-----BEGIN CERTIFICATE-----',
        cipher: 'CHACHA20-POLY1305:AES-256-GCM',
        authDigest: 'none',
        extraOptions: ['float', 'tls-version-min 1.3', 'explicit-exit-notify 2'],
      },
      secrets: {},
      warnings: [
        line('duplicate_directive', 'info', 'client', 6),
        line('duplicate_directive', 'info', 'pull', 7),
        line('duplicate_directive', 'info', 'tls-client', 8),
        line('verb_replaced', 'info', 'verb', 13),
        line('duplicate_directive', 'info', 'nobind', 15),
        line('script_security_dropped', 'warning', 'script-security', 20),
        { code: 'credentials_expected', severity: 'info', line: 50, message: 'no credentials' },
      ],
      missing: ['username', 'password'],
    };
    renderApp(routes({ 'POST /api/profiles/import': { body: mdexDraft } }), '/profiles');
    await screen.findByRole('cell', { name: 'Office' });
    chooseFile(
      ovpnFile('mdex fixed.IP.30 Router.ovpn', 'client\nremote openvpn30.mdex.de 1194 udp'),
    );

    expect(await screen.findByLabelText('Name')).toHaveValue('mdex fixed.IP.30 Router');
    const summary = screen.getByText('Still missing from the file').closest('[data-tone]');
    expect(summary).toHaveTextContent('Username');
    expect(summary).toHaveTextContent('Password');
    expect(summary).not.toHaveTextContent('CA certificate');
    expect(screen.getByLabelText('CA certificate')).not.toHaveAttribute('aria-invalid');

    expect(screen.getByText('6 notes')).toBeInTheDocument();
    expect(
      screen.getByText(/The file contains no client certificate and no username and password/),
    ).toBeInTheDocument();
    expect(
      screen.getByText('1 directive dropped or changed').closest('[data-tone]'),
    ).toHaveTextContent('script-security only allows scripts; TunnelDeck-VPN runs none');
    expect(screen.queryByText(/not imported/i)).not.toBeInTheDocument();
    expect(document.querySelector('[data-tone="danger"]')).toBeNull();
    expect(screen.queryByText('Traffic is not encrypted')).not.toBeInTheDocument();
  });

  it('decodes a Latin-1 file instead of garbling it', async () => {
    const { fetchMock } = renderApp(
      routes({ 'POST /api/profiles/import': { body: providerDraft } }),
      '/profiles',
    );
    await screen.findByRole('cell', { name: 'Office' });
    chooseFile(new File([new Uint8Array([0x23, 0x20, 0x42, 0xfc, 0x72, 0x6f])], 'b.ovpn'));

    await screen.findByLabelText('Name');
    const call = fetchMock.mock.calls.find(([url]) => url === '/api/profiles/import');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ protocol: 'openvpn', text: '# Büro' });
  });

  it('loads a file dropped onto the page and shows an overlay while dragging', async () => {
    renderApp(routes({ 'POST /api/profiles/import': { body: providerDraft } }), '/profiles');
    await screen.findByRole('cell', { name: 'Office' });
    const zone = screen.getByTestId('profile-drop-zone');
    const file = ovpnFile('office.conf');

    fireEvent.dragEnter(zone, dragEvent(file));
    expect(screen.getByRole('status')).toHaveTextContent('Drop the .ovpn file to load it');
    fireEvent.dragLeave(zone, dragEvent(file));
    expect(screen.queryByText('Drop the .ovpn file to load it')).not.toBeInTheDocument();

    fireEvent.dragEnter(zone, dragEvent(file));
    fireEvent.drop(zone, dragEvent(file));
    expect(screen.queryByText('Drop the .ovpn file to load it')).not.toBeInTheDocument();
    expect(await screen.findByLabelText('Name')).toHaveValue('office');
    expect(window.location.pathname).toBe('/profiles/new');
  });

  it('refuses a dropped file that is not a profile without sending it', async () => {
    const { fetchMock } = renderApp(routes(), '/profiles');
    await screen.findByRole('cell', { name: 'Office' });
    fireEvent.drop(screen.getByTestId('profile-drop-zone'), dragEvent(new File(['x'], 'cv.pdf')));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Could not load cv.pdf');
    expect(alert).toHaveTextContent('Only .ovpn or .conf files can be loaded.');
    expect(fetchMock.mock.calls.some(([url]) => url === '/api/profiles/import')).toBe(false);
  });

  it('names the file and the translated reason when the server refuses it', async () => {
    renderApp(
      routes({
        'POST /api/profiles/import': problem(422, 'validation_failed', 'invalid', {
          fields: { file: 'is empty' },
          fieldCodes: { file: { code: 'openvpn_file_empty' } },
        }),
      }),
      '/profiles',
    );
    await screen.findByRole('cell', { name: 'Office' });
    chooseFile(ovpnFile('empty.ovpn', ''));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Could not load empty.ovpn');
    expect(alert).toHaveTextContent('The file is empty or contains only comments.');
    expect(window.location.pathname).toBe('/profiles');
  });
});
