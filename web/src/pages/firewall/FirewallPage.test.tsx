import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { FirewallRule, FirewallState } from '../../api/firewall';
import { i18n } from '../../i18n';
import { problem, type MockRoutes } from '../../test/fetchMock';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const dsm: FirewallRule = {
  id: 'a',
  name: 'Admin UI',
  direction: 'inbound',
  action: 'accept',
  protocol: 'tcp',
  source: '203.0.113.0/24',
  destination: '192.168.1.10',
  destinationPort: { from: 5001 },
  keepSourceAddress: false,
  enabled: true,
  comment: '',
};

const web: FirewallRule = {
  id: 'b',
  name: 'Web server',
  direction: 'inbound',
  action: 'accept',
  protocol: 'tcp',
  source: '',
  destination: '192.168.1.2',
  destinationPort: { from: 443 },
  publicPort: { from: 4444 },
  keepSourceAddress: true,
  enabled: true,
  comment: '',
};

const office: FirewallRule = {
  id: 'c',
  name: 'Office network',
  direction: 'outbound',
  action: 'accept',
  protocol: 'any',
  source: '192.168.1.0/24',
  destination: '10.0.0.0/8',
  keepSourceAddress: false,
  enabled: true,
  comment: '',
};

const SETTINGS = { dropInvalid: true, mssClamp: true, synFloodProtection: true, pingLimit: true };

function state(overrides: Partial<FirewallState> = {}): FirewallState {
  return {
    rules: [dsm, office, web],
    settings: SETTINGS,
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
    'GET /api/firewall': { body: state() },
    ...overrides,
  };
}

async function openPage(overrides: MockRoutes = {}) {
  const result = renderApp(routes(overrides), '/firewall');
  await screen.findByRole('table', { name: 'Inbound from VPN' });
  return result;
}

function saveButton() {
  return screen.getByRole('button', { name: 'Save changes' });
}

function sentBody(fetchMock: ReturnType<typeof renderApp>['fetchMock'], method = 'PUT') {
  const call = fetchMock.mock.calls.find(([, init]) => init?.method === method);
  return JSON.parse(String(call?.[1]?.body)) as {
    rules: FirewallRule[];
    settings: typeof SETTINGS;
  };
}

function rowOf(name: string): HTMLElement {
  return screen.getByRole('cell', { name: new RegExp(`^${name}`) }).closest('tr') as HTMLElement;
}

describe('FirewallPage', () => {
  it('shows the host network and the rules of each direction in list order', async () => {
    await openPage();
    expect(
      screen.getByText('This device: 192.168.1.10 · Local LAN: 192.168.1.0/24 · IP forwarding: on'),
    ).toBeInTheDocument();
    const inbound = screen.getByRole('table', { name: 'Inbound from VPN' });
    const rows = within(inbound).getAllByRole('row').slice(1);
    expect(rows.map((row) => within(row).getAllByRole('cell')[2]?.textContent)).toEqual([
      'Admin UI',
      'Web server',
    ]);
    expect(
      within(inbound).getByText('203.0.113.0/24 :any → 192.168.1.10 :5001'),
    ).toBeInTheDocument();
    expect(
      within(inbound).getByText('any :any → 192.168.1.2 :443 (public 4444)'),
    ).toBeInTheDocument();
    expect(within(inbound).getByRole('img', { name: 'Source address kept' })).toBeInTheDocument();
    expect(within(inbound).queryByText('Office network')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: 'Outbound to VPN' }));
    const outbound = screen.getByRole('table', { name: 'Outbound to VPN' });
    expect(within(outbound).getByText('192.168.1.0/24 → 10.0.0.0/8')).toBeInTheDocument();
    expect(within(outbound).queryByText('Keep source')).not.toBeInTheDocument();
    expect(screen.getByText(/Devices must send this traffic to this host/)).toBeInTheDocument();
  });

  it('switches tabs with the arrow keys', async () => {
    await openPage();
    const inbound = screen.getByRole('tab', { name: 'Inbound from VPN' });
    expect(inbound).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(inbound, { key: 'ArrowRight' });
    expect(screen.getByRole('tab', { name: 'Outbound to VPN' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.getByRole('tab', { name: 'Outbound to VPN' })).toHaveFocus();
  });

  it('warns when IP forwarding is off and links to the docs', async () => {
    await openPage({ 'GET /api/firewall': { body: state({ ipForward: false }) } });
    const notice = screen.getByText(/IP forwarding: off/).closest('[data-tone]');
    expect(notice).toHaveAttribute('data-tone', 'warning');
    expect(
      within(notice as HTMLElement).getByRole('link', { name: 'How to turn it on' }),
    ).toHaveAttribute('href', expect.stringContaining('#ip-forwarding'));
  });

  it('enables Save and Discard only while something changed, and discards edits', async () => {
    await openPage();
    expect(saveButton()).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Discard' })).toBeDisabled();

    const enabled = screen.getByRole('checkbox', { name: 'Enabled: Admin UI' });
    fireEvent.click(enabled);
    expect(saveButton()).toBeEnabled();
    fireEvent.click(enabled);
    expect(saveButton()).toBeDisabled();

    fireEvent.click(screen.getByRole('switch', { name: 'Ping limit' }));
    expect(saveButton()).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.getByRole('switch', { name: 'Ping limit' })).toBeChecked();
    expect(saveButton()).toBeDisabled();
  });

  it('reorders rules within a direction and saves the new order', async () => {
    const { fetchMock } = await openPage({
      'PUT /api/firewall': { body: state({ rules: [web, office, dsm] }) },
    });
    expect(screen.getByRole('button', { name: 'Move Admin UI up' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Move Web server down' })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Move Web server up' }));
    fireEvent.click(saveButton());

    expect(await screen.findByText('Firewall saved.')).toBeInTheDocument();
    expect(sentBody(fetchMock).rules.map((rule) => rule.id)).toEqual(['b', 'c', 'a']);
    expect(sentBody(fetchMock).settings).toEqual(SETTINGS);
    expect(saveButton()).toBeDisabled();
  });

  it('shows editor fields by protocol and destination for inbound rules', async () => {
    await openPage();
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    const editor = screen.getByRole('region', { name: 'Edit rule' });
    const e = within(editor);

    expect(e.getByRole('combobox', { name: 'Protocol' })).toHaveValue('tcp+udp');
    const destination = e.getByRole('textbox', { name: 'Destination (address in the local LAN)' });
    expect(destination).toHaveValue('');
    expect(destination).toHaveAttribute('placeholder', '192.168.1.10');
    fireEvent.click(e.getByRole('button', { name: 'This device’s address: 192.168.1.10' }));
    expect(destination).toHaveValue('192.168.1.10');
    expect(
      e.queryByRole('button', { name: 'This device’s address: 192.168.1.10' }),
    ).not.toBeInTheDocument();
    expect(e.getByRole('combobox', { name: 'Action' })).toBeEnabled();
    expect(e.getByRole('textbox', { name: 'Source (optional)' })).toHaveAttribute(
      'placeholder',
      'Any',
    );
    expect(e.getByRole('textbox', { name: 'Source port (optional)' })).toHaveAttribute(
      'placeholder',
      'any',
    );
    expect(e.getByRole('textbox', { name: 'Destination port' })).toHaveAttribute(
      'placeholder',
      'any',
    );
    expect(e.getByRole('textbox', { name: 'Port on the VPN address' })).toBeDisabled();
    expect(e.queryByRole('checkbox', { name: 'Keep source address' })).not.toBeInTheDocument();
    expect(e.queryByRole('textbox', { name: /ICMP type/ })).not.toBeInTheDocument();

    fireEvent.change(destination, { target: { value: '192.168.1.3' } });
    expect(e.getByText('Must be inside the local LAN: 192.168.1.0/24')).toBeInTheDocument();
    expect(e.getByRole('textbox', { name: 'Port on the VPN address' })).toBeDisabled();
    fireEvent.change(e.getByRole('textbox', { name: 'Destination port' }), {
      target: { value: '443' },
    });
    expect(e.getByRole('textbox', { name: 'Port on the VPN address' })).toBeEnabled();
    expect(e.getByRole('checkbox', { name: 'Keep source address' })).toBeInTheDocument();
    expect(e.getByText('The device must route replies through this host.')).toBeInTheDocument();
    expect(e.getByRole('combobox', { name: 'Action' })).toBeDisabled();

    fireEvent.change(e.getByRole('combobox', { name: 'Protocol' }), { target: { value: 'icmp' } });
    expect(e.getByRole('textbox', { name: 'ICMP type (optional)' })).toBeInTheDocument();
    expect(e.queryByRole('textbox', { name: 'Destination port' })).not.toBeInTheDocument();

    fireEvent.change(e.getByRole('combobox', { name: 'Protocol' }), { target: { value: 'esp' } });
    expect(e.queryByRole('textbox', { name: /ICMP type/ })).not.toBeInTheDocument();
    expect(e.queryByRole('textbox', { name: 'Port on the VPN address' })).not.toBeInTheDocument();
    expect(e.queryByRole('textbox', { name: 'Source port (optional)' })).not.toBeInTheDocument();
  });

  it('sends a drop rule to this device’s own address without a public port', async () => {
    const { fetchMock } = await openPage({ 'PUT /api/firewall': { body: state() } });
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    const e = within(screen.getByRole('region', { name: 'Edit rule' }));
    fireEvent.change(e.getByRole('textbox', { name: 'Name' }), { target: { value: 'Block SSH' } });
    fireEvent.click(e.getByRole('button', { name: 'This device’s address: 192.168.1.10' }));
    fireEvent.change(e.getByRole('combobox', { name: 'Action' }), { target: { value: 'drop' } });
    fireEvent.change(e.getByRole('textbox', { name: 'Destination port' }), {
      target: { value: '22' },
    });
    expect(e.getByRole('textbox', { name: 'Port on the VPN address' })).toBeDisabled();
    expect(
      e.getByText('Rules to this device’s own address use the destination port.'),
    ).toBeInTheDocument();

    fireEvent.click(saveButton());
    await waitFor(() => expect(sentBody(fetchMock).rules).toHaveLength(4));
    expect(sentBody(fetchMock).rules[3]).toMatchObject({
      name: 'Block SSH',
      action: 'drop',
      destination: '192.168.1.10',
      destinationPort: { from: 22 },
      keepSourceAddress: false,
    });
    expect(sentBody(fetchMock).rules[3]).not.toHaveProperty('publicPort');
  });

  it('defaults the public port to the destination port', async () => {
    const { fetchMock } = await openPage({ 'PUT /api/firewall': { body: state() } });
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    const e = within(screen.getByRole('region', { name: 'Edit rule' }));
    fireEvent.change(e.getByRole('textbox', { name: 'Name' }), { target: { value: 'Storage' } });
    fireEvent.change(e.getByRole('textbox', { name: 'Destination (address in the local LAN)' }), {
      target: { value: '192.168.1.3' },
    });
    fireEvent.change(e.getByRole('textbox', { name: 'Destination port' }), {
      target: { value: '8000-8010' },
    });
    expect(e.getByRole('textbox', { name: 'Port on the VPN address' })).toHaveAttribute(
      'placeholder',
      '8000-8010',
    );
    expect(screen.getByText('any :any → 192.168.1.3 :8000-8010')).toBeInTheDocument();

    fireEvent.click(saveButton());
    await waitFor(() => expect(sentBody(fetchMock).rules).toHaveLength(4));
    expect(sentBody(fetchMock).rules[3]).toEqual({
      id: '',
      name: 'Storage',
      direction: 'inbound',
      action: 'accept',
      protocol: 'tcp+udp',
      source: '',
      destination: '192.168.1.3',
      destinationPort: { from: 8000, to: 8010 },
      keepSourceAddress: false,
      enabled: true,
      comment: '',
    });
  });

  it('forwards every port when the destination port is empty', async () => {
    const { fetchMock } = await openPage({ 'PUT /api/firewall': { body: state() } });
    fireEvent.click(screen.getByRole('button', { name: 'Edit Web server' }));
    const e = within(screen.getByRole('region', { name: 'Edit rule' }));
    expect(
      e.queryByText('Forwards every port of this protocol to the device, except the web UI ports.'),
    ).not.toBeInTheDocument();
    fireEvent.change(e.getByRole('textbox', { name: 'Destination port' }), {
      target: { value: '' },
    });
    expect(
      e.getByText('Forwards every port of this protocol to the device, except the web UI ports.'),
    ).toBeInTheDocument();
    const publicPort = e.getByRole('textbox', { name: 'Port on the VPN address' });
    expect(publicPort).toBeDisabled();
    expect(publicPort).toHaveValue('');
    expect(publicPort).toHaveAttribute('placeholder', 'any');
    expect(screen.getByText('any :any → 192.168.1.2 :any')).toBeInTheDocument();

    fireEvent.click(saveButton());
    await waitFor(() => expect(sentBody(fetchMock).rules).toHaveLength(3));
    const sent = sentBody(fetchMock).rules[2];
    expect(sent).not.toHaveProperty('destinationPort');
    expect(sent).not.toHaveProperty('publicPort');
  });

  it('shows coded API field errors in the UI language and others as sent', async () => {
    await i18n.changeLanguage('de');
    renderApp(
      routes({
        'PUT /api/firewall': problem(422, 'validation_failed', 'invalid', {
          fields: {
            'rules[0].destinationPort': 'a range covers at most 1000 ports',
            'rules[0].comment': 'server text without a code',
          },
          fieldCodes: {
            'rules[0].destinationPort': { code: 'port_range_too_long', params: { max: '1000' } },
          },
        }),
      }),
      '/firewall',
    );
    await screen.findByRole('table', { name: 'Eingehend vom VPN' });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Aktiv: Admin UI' }));
    fireEvent.click(screen.getByRole('button', { name: 'Änderungen speichern' }));

    const e = within(await screen.findByRole('region', { name: 'Regel bearbeiten' }));
    expect(e.getByText('Ein Bereich umfasst höchstens 1000 Ports.')).toBeInTheDocument();
    expect(e.getByText('server text without a code')).toBeInTheDocument();
    expect(e.queryByText('a range covers at most 1000 ports')).not.toBeInTheDocument();
  });

  it('edits outbound rules with a required source and no public port', async () => {
    await openPage();
    fireEvent.click(screen.getByRole('tab', { name: 'Outbound to VPN' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    const e = within(screen.getByRole('region', { name: 'Edit rule' }));
    expect(e.queryByRole('button', { name: /This device’s address/ })).not.toBeInTheDocument();
    expect(e.getByRole('textbox', { name: 'Source (LAN device or subnet)' })).toBeRequired();
    expect(
      e.getByRole('textbox', { name: 'Destination (address or network behind the VPN)' }),
    ).toHaveAttribute('placeholder', '10.0.0.0/8 or 0.0.0.0/0');
    expect(e.getByRole('combobox', { name: 'Protocol' })).toHaveValue('any');

    fireEvent.change(e.getByRole('combobox', { name: 'Protocol' }), { target: { value: 'tcp' } });
    expect(e.getByRole('textbox', { name: 'Destination port' })).toBeInTheDocument();
    expect(e.queryByRole('textbox', { name: 'Port on the VPN address' })).not.toBeInTheDocument();
    expect(e.queryByRole('checkbox', { name: 'Keep source address' })).not.toBeInTheDocument();
  });

  it('duplicates and deletes rules after an inline confirmation', async () => {
    await openPage();
    fireEvent.click(screen.getByRole('button', { name: 'Duplicate Admin UI' }));
    expect(screen.getByRole('cell', { name: 'Admin UI (copy)' })).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Name' })).toHaveValue('Admin UI (copy)');

    fireEvent.click(screen.getByRole('button', { name: 'Delete Admin UI (copy)' }));
    const confirm = screen.getByRole('group', { name: 'Confirm deletion' });
    fireEvent.click(within(confirm).getByRole('button', { name: 'Delete rule' }));
    expect(screen.queryByRole('cell', { name: 'Admin UI (copy)' })).not.toBeInTheDocument();
    expect(saveButton()).toBeDisabled();
  });

  it('inserts the IPsec template rules into both tabs, highlighted until saved', async () => {
    const template: FirewallRule[] = [
      {
        ...web,
        id: '',
        name: 'Router: IKE',
        protocol: 'udp',
        destinationPort: { from: 500 },
        publicPort: undefined,
      },
      {
        ...office,
        id: '',
        name: 'Router: outbound ESP',
        protocol: 'esp',
        source: '192.168.1.2',
        destination: '0.0.0.0/0',
      },
    ];
    const { fetchMock } = await openPage({
      'POST /api/firewall/templates/ipsec': { body: { rules: template } },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add IPsec router' }));
    const form = within(screen.getByRole('form', { name: 'IPsec router' }));
    fireEvent.change(form.getByRole('textbox', { name: 'Name' }), { target: { value: 'Router' } });
    fireEvent.change(form.getByRole('textbox', { name: 'Router address' }), {
      target: { value: '192.168.1.2' },
    });
    fireEvent.change(form.getByRole('textbox', { name: 'Peer addresses (optional), line 1' }), {
      target: { value: '198.51.100.7' },
    });
    fireEvent.click(form.getByRole('button', { name: 'Add rules' }));

    expect(
      await screen.findByText('2 rules added. Save changes to apply them.'),
    ).toBeInTheDocument();
    expect(sentBody(fetchMock, 'POST')).toEqual({
      name: 'Router',
      deviceAddress: '192.168.1.2',
      peers: ['198.51.100.7'],
    });
    expect(rowOf('Router: IKE')).toHaveAttribute('data-state', 'highlighted');
    expect(within(rowOf('Router: IKE')).getByText('Not saved')).toBeInTheDocument();
    expect(saveButton()).toBeEnabled();

    fireEvent.click(screen.getByRole('tab', { name: 'Outbound to VPN' }));
    expect(rowOf('Router: outbound ESP')).toHaveAttribute('data-state', 'highlighted');
  });

  it('shows template field errors in the form', async () => {
    await openPage({
      'POST /api/firewall/templates/ipsec': problem(422, 'validation_failed', 'invalid', {
        fields: { deviceAddress: 'must be inside a LAN subnet' },
      }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add IPsec router' }));
    const form = within(screen.getByRole('form', { name: 'IPsec router' }));
    fireEvent.change(form.getByRole('textbox', { name: 'Name' }), { target: { value: 'X' } });
    fireEvent.change(form.getByRole('textbox', { name: 'Router address' }), {
      target: { value: '10.1.1.1' },
    });
    fireEvent.click(form.getByRole('button', { name: 'Add rules' }));
    expect(await form.findByText('must be inside a LAN subnet')).toBeInTheDocument();
  });

  it('opens the editor of the first rule with API errors, on its tab', async () => {
    await openPage({
      'PUT /api/firewall': problem(422, 'validation_failed', 'invalid', {
        fields: { 'rules[1].destination': 'must be an IPv4 address or a network' },
      }),
    });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enabled: Admin UI' }));
    fireEvent.click(saveButton());

    expect(await screen.findByText('Some rules need attention.')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Outbound to VPN' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    const e = within(screen.getByRole('region', { name: 'Edit rule' }));
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('Office network');
    expect(
      e.getByRole('textbox', { name: 'Destination (address or network behind the VPN)' }),
    ).toHaveAttribute('aria-invalid', 'true');
    expect(e.getByText('must be an IPv4 address or a network')).toBeInTheDocument();
    expect(within(rowOf('Office network')).getByText('Needs attention')).toBeInTheDocument();
  });

  it('rejects malformed ports before sending', async () => {
    const { fetchMock } = await openPage();
    fireEvent.click(screen.getByRole('button', { name: 'Edit Admin UI' }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Destination port' }), {
      target: { value: 'https' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    fireEvent.click(saveButton());

    expect(
      await screen.findByText('Enter a port or a range such as 8000-8010.'),
    ).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(false);
  });

  it('clears earlier field errors when saving again', async () => {
    await openPage({
      'PUT /api/firewall': [
        problem(422, 'validation_failed', 'invalid', { fields: { 'rules[0].name': 'bad' } }),
        problem(500, 'firewall_failed', 'iptables missing'),
      ],
    });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enabled: Admin UI' }));
    fireEvent.click(saveButton());
    expect(await screen.findByText('Some rules need attention.')).toBeInTheDocument();

    fireEvent.click(saveButton());
    expect(await screen.findByText('iptables missing')).toBeInTheDocument();
    expect(screen.queryByText('Some rules need attention.')).not.toBeInTheDocument();
    expect(screen.queryByText('Needs attention')).not.toBeInTheDocument();
  });

  it('shows a failed apply with its detail and keeps the edits', async () => {
    await openPage({
      'PUT /api/firewall': problem(
        500,
        'firewall_failed',
        'The firewall could not be applied; the previous configuration was restored. iptables: no chain',
      ),
    });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enabled: Admin UI' }));
    fireEvent.click(saveButton());

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('The firewall could not be applied');
    expect(alert).toHaveTextContent('iptables: no chain');
    expect(alert.closest('[data-tone]')).toHaveAttribute('data-tone', 'danger');
    expect(screen.getByRole('checkbox', { name: 'Enabled: Admin UI' })).not.toBeChecked();
    expect(saveButton()).toBeEnabled();
  });
});
