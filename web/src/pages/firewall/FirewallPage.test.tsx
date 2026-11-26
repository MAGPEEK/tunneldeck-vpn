import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { FirewallRule, FirewallState, LanDevice } from '../../api/firewall';
import { i18n } from '../../i18n';
import { problem, type MockRoutes } from '../../test/fetchMock';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const admin: FirewallRule = {
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
  name: 'Web',
  direction: 'inbound',
  action: 'accept',
  protocol: 'tcp',
  source: '',
  destination: '192.168.1.20',
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
  enabled: false,
  comment: '',
};

const SETTINGS = { dropInvalid: true, mssClamp: true, synFloodProtection: true, pingLimit: true };

const DEVICES: LanDevice[] = [
  {
    address: '192.168.1.20',
    mac: '02:00:00:00:00:20',
    name: 'Web server',
    state: 'REACHABLE',
    onLan: true,
  },
  { address: '192.168.1.30', mac: '02:00:00:00:00:30', state: 'STALE', onLan: true },
  { address: '192.168.1.10', mac: '02:00:00:00:00:10', state: 'REACHABLE', onLan: true },
];

function state(overrides: Partial<FirewallState> = {}): FirewallState {
  return {
    rules: [admin, office, web],
    settings: SETTINGS,
    hostAddress: '192.168.1.10',
    hostAddresses: ['192.168.1.10'],
    lanSubnets: ['192.168.1.0/24'],
    ipForward: true,
    counters: { a: { packets: 12, bytes: 720 }, b: { packets: 1, bytes: 60 } },
    countersAvailable: true,
    ...overrides,
  };
}

function routes(overrides: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/firewall': { body: state() },
    'GET /api/firewall/devices': { body: { devices: DEVICES } },
    ...overrides,
  };
}

async function openPage(overrides: MockRoutes = {}) {
  const result = renderApp(routes(overrides), '/firewall');
  await screen.findByRole('list', { name: 'Rules in evaluation order' });
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

function row(name: string): HTMLElement {
  return screen.getByRole('listitem', { name });
}

function rowNames(): string[] {
  const list = screen.getByRole('list', { name: 'Rules in evaluation order' });
  return within(list)
    .getAllByRole('listitem')
    .map((item) => item.getAttribute('aria-label') ?? '');
}

async function chooseIntent(title: string) {
  fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
  fireEvent.click(screen.getByRole('button', { name: title }));
  return within(screen.getByRole('region', { name: title }));
}

describe('FirewallPage', () => {
  it('lists every rule in evaluation order with flow strip, plain line and hits', async () => {
    await openPage();
    expect(
      screen.getByText('This device: 192.168.1.10 · Local LAN: 192.168.1.0/24 · IP forwarding: on'),
    ).toBeInTheDocument();
    expect(rowNames()).toEqual(['Admin UI', 'Office network', 'Web']);

    const adminRow = within(row('Admin UI'));
    expect(adminRow.getByTestId('flow')).toHaveTextContent(
      'VPN · 203.0.113.0/24 to Local LAN · This device',
    );
    expect(adminRow.getByText('Admin UI · TCP 5001')).toBeInTheDocument();
    expect(adminRow.getByText('12 hits')).toBeInTheDocument();

    const webRow = within(row('Web'));
    await waitFor(() =>
      expect(webRow.getByTestId('flow')).toHaveTextContent('VPN · any to Local LAN · Web server'),
    );
    expect(webRow.getByText('Local LAN').closest('[data-accent]')).not.toBeNull();
    expect(
      webRow.getByText('Web · HTTPS (TCP 443) · VPN port 4444 · sender kept'),
    ).toBeInTheDocument();
    expect(webRow.getByText('1 hit')).toBeInTheDocument();

    const officeRow = within(row('Office network'));
    expect(officeRow.getByTestId('flow')).toHaveTextContent(
      'Local LAN · 192.168.1.0/24 to VPN · 10.0.0.0/8',
    );
    expect(officeRow.getByText('Office network · all ports · off')).toBeInTheDocument();
    expect(officeRow.getByText('No hits counted')).toBeInTheDocument();
  });

  it('hides the hit counters when they are not available', async () => {
    await openPage({
      'GET /api/firewall': { body: state({ counters: null, countersAvailable: false }) },
    });
    expect(screen.queryByText('12 hits')).not.toBeInTheDocument();
    expect(screen.queryByText('No hits counted')).not.toBeInTheDocument();
  });

  it('filters the list by direction', async () => {
    await openPage();
    expect(screen.getByRole('button', { name: 'All' })).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(screen.getByRole('button', { name: 'Inbound' }));
    expect(rowNames()).toEqual(['Admin UI', 'Web']);
    fireEvent.click(screen.getByRole('button', { name: 'Outbound' }));
    expect(rowNames()).toEqual(['Office network']);
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

    const enabled = screen.getByRole('switch', { name: 'Enabled: Admin UI' });
    fireEvent.click(enabled);
    expect(saveButton()).toBeEnabled();
    expect(within(row('Admin UI')).getByText('No hits counted')).toBeInTheDocument();
    fireEvent.click(enabled);
    expect(saveButton()).toBeDisabled();

    fireEvent.click(screen.getByRole('switch', { name: 'Ping limit' }));
    expect(saveButton()).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.getByRole('switch', { name: 'Ping limit' })).toBeChecked();
    expect(saveButton()).toBeDisabled();
  });

  it('reorders the whole list, or within the filter, and saves the new order', async () => {
    const { fetchMock } = await openPage({
      'PUT /api/firewall': { body: state({ rules: [web, admin, office] }) },
    });
    expect(screen.getByRole('button', { name: 'Move Admin UI up' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Move Web down' })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Move Web up' }));
    expect(rowNames()).toEqual(['Admin UI', 'Web', 'Office network']);
    fireEvent.click(screen.getByRole('button', { name: 'Inbound' }));
    fireEvent.click(screen.getByRole('button', { name: 'Move Web up' }));
    fireEvent.click(saveButton());

    expect(await screen.findByText('Firewall saved.')).toBeInTheDocument();
    expect(sentBody(fetchMock).rules.map((rule) => rule.id)).toEqual(['b', 'a', 'c']);
    expect(sentBody(fetchMock).settings).toEqual(SETTINGS);
    expect(saveButton()).toBeDisabled();
  });

  it('offers one card per intent, usable by keyboard', async () => {
    await openPage();
    const add = screen.getByRole('button', { name: 'Add rule' });
    expect(add).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(add);
    const cards = within(screen.getByRole('region', { name: 'What do you want to do?' }));
    expect(cards.getAllByRole('button').map((card) => card.textContent)).toEqual([
      expect.stringMatching(/^Make a LAN device reachable from the VPN/),
      expect.stringMatching(/^Open a service on this device/),
      expect.stringMatching(/^Let a LAN device into the VPN/),
      expect.stringMatching(/^IPsec router/),
      expect.stringMatching(/^Block something/),
      expect.stringMatching(/^Custom rule/),
    ]);
    expect(cards.getByRole('button', { name: 'Custom rule' })).toHaveAccessibleDescription(
      'Set every field yourself.',
    );
  });

  it('makes a LAN device reachable: device picker, service presets, name, summary', async () => {
    const { fetchMock } = await openPage({ 'PUT /api/firewall': { body: state() } });
    const e = await chooseIntent('Make a LAN device reachable from the VPN');

    expect(e.queryByRole('combobox', { name: 'Action' })).not.toBeInTheDocument();
    expect(e.queryByRole('combobox', { name: 'Direction' })).not.toBeInTheDocument();
    expect(e.getByRole('radio', { name: /HTTPS/ })).toBeChecked();
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('HTTPS');

    const devices = within(e.getByRole('list', { name: 'Devices in the local LAN' }));
    expect(devices.getAllByRole('button').map((button) => button.textContent)).toEqual([
      'Web server192.168.1.2002:00:00:00:00:20',
      'Unnamed device192.168.1.3002:00:00:00:00:30',
    ]);
    fireEvent.click(devices.getByRole('button', { name: /Web server/ }));
    expect(devices.getByRole('button', { name: /Web server/ })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    const address = e.getByRole('textbox', { name: 'Device address' });
    expect(address).toHaveValue('192.168.1.20');
    expect(e.getByText(/Reserve this address in your router/)).toBeInTheDocument();
    expect(e.getByTestId('flow')).toHaveTextContent('VPN · any to Local LAN · Web server');
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('Web server HTTPS');

    fireEvent.click(e.getByRole('radio', { name: /SSH/ }));
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('Web server SSH');
    expect(
      e.getByText(
        'Connections from any sender to the VPN address on TCP port 22 go to Web server (192.168.1.20) on TCP port 22.',
      ),
    ).toBeInTheDocument();
    expect(e.getByText('Web server sees this device as the sender.')).toBeInTheDocument();

    fireEvent.change(e.getByRole('textbox', { name: 'Name' }), { target: { value: 'Shell' } });
    fireEvent.click(e.getByRole('radio', { name: /RDP/ }));
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('Shell');

    fireEvent.click(saveButton());
    await waitFor(() => expect(sentBody(fetchMock).rules).toHaveLength(4));
    expect(sentBody(fetchMock).rules[3]).toEqual({
      id: '',
      name: 'Shell',
      direction: 'inbound',
      action: 'accept',
      protocol: 'tcp',
      source: '',
      destination: '192.168.1.20',
      destinationPort: { from: 3389 },
      keepSourceAddress: false,
      enabled: true,
      comment: '',
    });
  });

  it('accepts a free address and offers this device’s own address', async () => {
    await openPage();
    const e = await chooseIntent('Make a LAN device reachable from the VPN');
    const address = e.getByRole('textbox', { name: 'Device address' });
    expect(address).toHaveAttribute('placeholder', '192.168.1.10');
    fireEvent.change(address, { target: { value: '192.168.1.44' } });
    expect(e.getByTestId('flow')).toHaveTextContent('Local LAN · 192.168.1.44');
    expect(e.getByText(/Must be inside the local LAN: 192.168.1.0\/24./)).toBeInTheDocument();

    fireEvent.click(e.getByRole('button', { name: 'This device’s address: 192.168.1.10' }));
    expect(address).toHaveValue('192.168.1.10');
    expect(e.getByTestId('flow')).toHaveTextContent('Local LAN · This device');
    expect(e.queryByText(/Reserve this address/)).not.toBeInTheDocument();
    expect(
      e.queryByRole('button', { name: 'This device’s address: 192.168.1.10' }),
    ).not.toBeInTheDocument();
  });

  it('says so when the device list is not available', async () => {
    await openPage({
      'GET /api/firewall/devices': problem(500, 'internal', 'ip neigh failed'),
    });
    const e = await chooseIntent('Make a LAN device reachable from the VPN');
    expect(
      await e.findByText('The device list is not available. Enter an address.'),
    ).toBeInTheDocument();
    expect(e.getByRole('textbox', { name: 'Device address' })).toBeInTheDocument();
  });

  it('shows protocol and port fields for a custom service', async () => {
    await openPage();
    const e = await chooseIntent('Make a LAN device reachable from the VPN');
    fireEvent.click(e.getByRole('radio', { name: /DNS/ }));
    fireEvent.click(e.getByRole('radio', { name: 'Custom' }));
    expect(e.getByRole('combobox', { name: 'Protocol' })).toHaveValue('tcp+udp');
    expect(e.getByRole('textbox', { name: 'Destination port' })).toHaveValue('53');

    fireEvent.change(e.getByRole('combobox', { name: 'Protocol' }), { target: { value: 'icmp' } });
    expect(e.getByRole('textbox', { name: 'ICMP type (optional)' })).toBeInTheDocument();
    expect(e.queryByRole('textbox', { name: 'Destination port' })).not.toBeInTheDocument();

    fireEvent.click(e.getByRole('radio', { name: /All ports/ }));
    expect(e.queryByRole('combobox', { name: 'Protocol' })).not.toBeInTheDocument();
  });

  it('shows the advanced fields and what a port forward creates', async () => {
    await openPage();
    const e = await chooseIntent('Make a LAN device reachable from the VPN');
    fireEvent.change(e.getByRole('textbox', { name: 'Device address' }), {
      target: { value: '192.168.1.30' },
    });
    fireEvent.click(e.getByText('Restrict and advanced'));
    expect(e.getByRole('textbox', { name: 'Sender address (optional)' })).toHaveAttribute(
      'placeholder',
      'Any',
    );
    expect(e.getByRole('textbox', { name: 'Sender port (optional)' })).toHaveAttribute(
      'placeholder',
      'any',
    );
    const vpnPort = e.getByRole('textbox', { name: 'Port on the VPN address' });
    expect(vpnPort).toHaveAttribute('placeholder', '443');
    fireEvent.change(vpnPort, { target: { value: '8443' } });
    fireEvent.change(e.getByRole('textbox', { name: 'Sender address (optional)' }), {
      target: { value: '198.51.100.0/24' },
    });
    fireEvent.click(e.getByRole('radio', { name: 'Original sender' }));
    expect(
      e.getByText(/must send its replies back through this device, for example/),
    ).toBeInTheDocument();
    expect(e.getByRole('textbox', { name: 'Comment (optional)' })).toBeInTheDocument();

    fireEvent.click(e.getByText('What this rule creates'));
    expect(
      e
        .getAllByRole('listitem')
        .map((item) => item.textContent)
        .slice(-3),
    ).toEqual([
      'Forward filter: allow TCP 443 from 198.51.100.0/24 to 192.168.1.30',
      'Destination NAT: TCP 8443 on the VPN address goes to 192.168.1.30:443',
      'Policy route: replies from 192.168.1.30 leave through the VPN',
    ]);
    expect(
      e.getByText(
        'Connections from 198.51.100.0/24 to the VPN address on TCP port 8443 go to 192.168.1.30 on TCP port 443.',
      ),
    ).toBeInTheDocument();
  });

  it('opens a service on this device with its own address prefilled', async () => {
    const { fetchMock } = await openPage({ 'PUT /api/firewall': { body: state() } });
    const e = await chooseIntent('Open a service on this device');
    expect(e.getByRole('textbox', { name: 'Device address' })).toHaveValue('192.168.1.10');
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('This device HTTPS');
    expect(
      e.getByText(
        'Connections from any sender to this device (192.168.1.10) on TCP port 443 are allowed.',
      ),
    ).toBeInTheDocument();
    fireEvent.click(e.getByText('Restrict and advanced'));
    expect(e.queryByRole('textbox', { name: 'Port on the VPN address' })).not.toBeInTheDocument();
    expect(e.queryByRole('radio', { name: 'Original sender' })).not.toBeInTheDocument();
    fireEvent.click(e.getByText('What this rule creates'));
    expect(
      e.getByText('Input filter: allow TCP 443 from any sender to 192.168.1.10'),
    ).toBeInTheDocument();

    fireEvent.click(e.getByRole('button', { name: 'Done' }));
    fireEvent.click(saveButton());
    await waitFor(() => expect(sentBody(fetchMock).rules).toHaveLength(4));
    expect(sentBody(fetchMock).rules[3]).toMatchObject({
      name: 'This device HTTPS',
      destination: '192.168.1.10',
      destinationPort: { from: 443 },
    });
  });

  it('lets a LAN device into the VPN with everything behind it by default', async () => {
    const { fetchMock } = await openPage({ 'PUT /api/firewall': { body: state() } });
    const e = await chooseIntent('Let a LAN device into the VPN');
    expect(e.queryByRole('textbox', { name: 'Device address' })).not.toBeInTheDocument();
    expect(e.queryByRole('button', { name: /This device’s address/ })).not.toBeInTheDocument();
    expect(e.getByText(/set it as its gateway or add a route/)).toBeInTheDocument();
    fireEvent.click(e.getByRole('button', { name: /Web server/ }));
    expect(e.getByRole('textbox', { name: 'Device or subnet address' })).toHaveValue(
      '192.168.1.20',
    );
    expect(
      e.getByRole('textbox', { name: 'Address or network behind the VPN (optional)' }),
    ).toHaveValue('');
    expect(e.getByRole('radio', { name: 'All ports' })).toBeChecked();
    expect(e.getByTestId('flow')).toHaveTextContent('Local LAN · Web server to VPN · any');
    expect(e.getByText('While the VPN is down, this traffic is blocked.')).toBeInTheDocument();
    fireEvent.click(e.getByText('Restrict and advanced'));
    expect(e.queryByRole('textbox', { name: 'Sender address (optional)' })).not.toBeInTheDocument();

    fireEvent.click(saveButton());
    await waitFor(() => expect(sentBody(fetchMock).rules).toHaveLength(4));
    expect(sentBody(fetchMock).rules[3]).toMatchObject({
      name: 'Web server All ports',
      direction: 'outbound',
      protocol: 'any',
      source: '192.168.1.20',
      destination: '0.0.0.0/0',
    });
  });

  it('blocks something on this device with drop or reject', async () => {
    const { fetchMock } = await openPage({ 'PUT /api/firewall': { body: state() } });
    const e = await chooseIntent('Block something');
    const action = e.getByRole('combobox', { name: 'Action' });
    expect(action).toBeEnabled();
    expect(action).toHaveValue('drop');
    expect(
      within(action)
        .getAllByRole('option')
        .map((option) => option.textContent),
    ).toEqual(['Drop', 'Reject']);
    expect(e.getByRole('textbox', { name: 'Device address' })).toHaveValue('192.168.1.10');
    expect(e.getByRole('radio', { name: 'All ports' })).toBeChecked();
    fireEvent.change(action, { target: { value: 'reject' } });
    fireEvent.click(e.getByText('Restrict and advanced'));
    fireEvent.change(e.getByRole('textbox', { name: 'Sender address (optional)' }), {
      target: { value: '198.51.100.7' },
    });
    expect(
      e.getByText('Connections from 198.51.100.7 to this device (192.168.1.10) are refused.'),
    ).toBeInTheDocument();

    fireEvent.click(saveButton());
    await waitFor(() => expect(sentBody(fetchMock).rules).toHaveLength(4));
    expect(sentBody(fetchMock).rules[3]).toMatchObject({
      action: 'reject',
      protocol: 'any',
      source: '198.51.100.7',
      destination: '192.168.1.10',
    });
  });

  it('builds a custom rule with an editable action from the start', async () => {
    await openPage();
    const e = await chooseIntent('Custom rule');
    expect(e.getByRole('combobox', { name: 'Direction' })).toHaveValue('inbound');
    const action = e.getByRole('combobox', { name: 'Action' });
    expect(action).toBeEnabled();
    fireEvent.change(action, { target: { value: 'drop' } });
    expect(action).toHaveValue('drop');

    fireEvent.change(e.getByRole('textbox', { name: 'Device address' }), {
      target: { value: '192.168.1.30' },
    });
    expect(action).toBeDisabled();
    expect(action).toHaveValue('accept');
    expect(e.getByText(/Rules to other devices always allow/)).toBeInTheDocument();

    fireEvent.change(e.getByRole('combobox', { name: 'Direction' }), {
      target: { value: 'outbound' },
    });
    expect(e.getByRole('textbox', { name: 'Device or subnet address' })).toBeInTheDocument();
    expect(
      e.getByRole('textbox', { name: 'Address or network behind the VPN (optional)' }),
    ).toBeInTheDocument();
  });

  it('removes a new rule on Cancel', async () => {
    await openPage();
    const e = await chooseIntent('Custom rule');
    expect(rowNames()).toHaveLength(4);
    fireEvent.click(e.getByRole('button', { name: 'Cancel' }));
    expect(rowNames()).toEqual(['Admin UI', 'Office network', 'Web']);
    expect(saveButton()).toBeDisabled();
  });

  it('edits an existing rule with the steps of its intent', async () => {
    await openPage();
    fireEvent.click(screen.getByRole('button', { name: 'Edit Web' }));
    const e = within(screen.getByRole('region', { name: 'Edit rule' }));
    expect(e.getByRole('textbox', { name: 'Device address' })).toHaveValue('192.168.1.20');
    expect(e.getByRole('radio', { name: /HTTPS/ })).toBeChecked();
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('Web');
    fireEvent.click(e.getByRole('radio', { name: /^HTTP ?80/ }));
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('Web');
    expect(e.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
  });

  it('duplicates and deletes rules after an inline confirmation', async () => {
    await openPage();
    fireEvent.click(screen.getByRole('button', { name: 'Duplicate Admin UI' }));
    expect(rowNames()).toEqual(['Admin UI', 'Admin UI (copy)', 'Office network', 'Web']);
    expect(screen.getByRole('textbox', { name: 'Name' })).toHaveValue('Admin UI (copy)');

    fireEvent.click(screen.getByRole('button', { name: 'Delete Admin UI (copy)' }));
    const confirm = screen.getByRole('group', { name: 'Confirm deletion' });
    fireEvent.click(within(confirm).getByRole('button', { name: 'Delete rule' }));
    expect(rowNames()).toEqual(['Admin UI', 'Office network', 'Web']);
    expect(saveButton()).toBeDisabled();
  });

  it('inserts the IPsec template rules, highlighted until saved', async () => {
    const template: FirewallRule[] = [
      { ...web, id: '', name: 'Router: IKE', protocol: 'udp', destinationPort: { from: 500 } },
      {
        ...office,
        id: '',
        name: 'Router: outbound ESP',
        protocol: 'esp',
        source: '192.168.1.2',
        destination: '0.0.0.0/0',
        enabled: true,
      },
    ];
    const { fetchMock } = await openPage({
      'POST /api/firewall/templates/ipsec': { body: { rules: template } },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    fireEvent.click(screen.getByRole('button', { name: 'IPsec router' }));
    const form = within(screen.getByRole('form', { name: 'IPsec router' }));
    fireEvent.change(form.getByRole('textbox', { name: 'Name' }), { target: { value: 'Router' } });
    expect(form.queryByRole('button', { name: /This device’s address/ })).not.toBeInTheDocument();
    fireEvent.click(form.getByRole('button', { name: /Unnamed device/ }));
    expect(form.getByRole('textbox', { name: 'Router address' })).toHaveValue('192.168.1.30');
    fireEvent.change(form.getByRole('textbox', { name: 'Peer addresses (optional), line 1' }), {
      target: { value: '198.51.100.7' },
    });
    fireEvent.click(form.getByRole('button', { name: 'Add rules' }));

    expect(
      await screen.findByText('2 rules added. Save changes to apply them.'),
    ).toBeInTheDocument();
    expect(sentBody(fetchMock, 'POST')).toEqual({
      name: 'Router',
      deviceAddress: '192.168.1.30',
      peers: ['198.51.100.7'],
    });
    expect(row('Router: IKE')).toHaveAttribute('data-state', 'highlighted');
    expect(within(row('Router: IKE')).getByText('Not saved')).toBeInTheDocument();
    expect(row('Router: outbound ESP')).toHaveAttribute('data-state', 'highlighted');
    expect(saveButton()).toBeEnabled();
  });

  it('shows template field errors in the form', async () => {
    await openPage({
      'POST /api/firewall/templates/ipsec': problem(422, 'validation_failed', 'invalid', {
        fields: { deviceAddress: 'must be inside a LAN subnet' },
      }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    fireEvent.click(screen.getByRole('button', { name: 'IPsec router' }));
    const form = within(screen.getByRole('form', { name: 'IPsec router' }));
    fireEvent.change(form.getByRole('textbox', { name: 'Name' }), { target: { value: 'X' } });
    fireEvent.change(form.getByRole('textbox', { name: 'Router address' }), {
      target: { value: '10.1.1.1' },
    });
    fireEvent.click(form.getByRole('button', { name: 'Add rules' }));
    expect(await form.findByText('must be inside a LAN subnet')).toBeInTheDocument();
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
    await screen.findByRole('list', { name: 'Regeln in Auswertungsreihenfolge' });
    fireEvent.click(screen.getByRole('switch', { name: 'Aktiv: Admin UI' }));
    fireEvent.click(screen.getByRole('button', { name: 'Änderungen speichern' }));

    const e = within(await screen.findByRole('region', { name: 'Regel bearbeiten' }));
    expect(e.getByRole('radio', { name: 'Eigene Angabe' })).toBeChecked();
    expect(e.getByText('Ein Bereich umfasst höchstens 1000 Ports.')).toBeInTheDocument();
    expect(e.getByText('server text without a code')).toBeVisible();
    expect(e.queryByText('a range covers at most 1000 ports')).not.toBeInTheDocument();
  });

  it('opens the editor of the first rule with API errors, with the field marked', async () => {
    await openPage({
      'PUT /api/firewall': problem(422, 'validation_failed', 'invalid', {
        fields: {
          'rules[1].destination': 'must be an IPv4 address or a network',
          'rules[2].publicPort': 'taken',
        },
      }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Outbound' }));
    fireEvent.click(screen.getByRole('switch', { name: 'Enabled: Office network' }));
    fireEvent.click(saveButton());

    expect(await screen.findByText('Some rules need attention.')).toBeInTheDocument();
    const e = within(screen.getByRole('region', { name: 'Edit rule' }));
    expect(e.getByRole('textbox', { name: 'Name' })).toHaveValue('Office network');
    expect(
      e.getByRole('textbox', { name: 'Address or network behind the VPN (optional)' }),
    ).toHaveAttribute('aria-invalid', 'true');
    expect(e.getByText('must be an IPv4 address or a network')).toBeInTheDocument();
    expect(within(row('Office network')).getByText('Needs attention')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'All' }));
    fireEvent.click(screen.getByRole('button', { name: 'Edit Web' }));
    const web = within(screen.getByRole('region', { name: 'Edit rule' }));
    expect(web.getByRole('textbox', { name: 'Port on the VPN address' })).toBeVisible();
  });

  it('rejects malformed ports before sending', async () => {
    const { fetchMock } = await openPage();
    fireEvent.click(screen.getByRole('button', { name: 'Edit Admin UI' }));
    const e = within(screen.getByRole('region', { name: 'Edit rule' }));
    fireEvent.change(e.getByRole('textbox', { name: 'Destination port' }), {
      target: { value: 'https' },
    });
    fireEvent.click(e.getByRole('button', { name: 'Done' }));
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
    fireEvent.click(screen.getByRole('switch', { name: 'Enabled: Admin UI' }));
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
    fireEvent.click(screen.getByRole('switch', { name: 'Enabled: Admin UI' }));
    fireEvent.click(saveButton());

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('The firewall could not be applied');
    expect(alert).toHaveTextContent('iptables: no chain');
    expect(alert.closest('[data-tone]')).toHaveAttribute('data-tone', 'danger');
    expect(screen.getByRole('switch', { name: 'Enabled: Admin UI' })).not.toBeChecked();
    expect(saveButton()).toBeEnabled();
  });
});
