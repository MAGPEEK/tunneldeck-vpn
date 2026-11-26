import { act, fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ConnectionState, ConnectionStatus } from '../../api/connection';
import { makeFirewall, makeProfile, makeStatus } from '../../test/fixtures';
import { renderWithProviders } from '../../test/renderWithProviders';
import { ConnectionCard, type ConnectionCardProps } from './ConnectionCard';

const office = makeProfile();
const mdex = makeProfile({
  id: 'p2',
  name: 'mdex',
  settings: { remoteHost: 'publicip20.mdex.de', port: 1194 },
  advisories: [
    { code: 'no_dco', severity: 'info' },
    { code: 'unencrypted_data_channel', severity: 'danger', field: 'cipher' },
    { code: 'weak_digest', severity: 'warning', field: 'authDigest' },
  ],
});

function renderCard(status: Partial<ConnectionStatus>, props: Partial<ConnectionCardProps> = {}) {
  const handlers = { onConnect: vi.fn(), onDisconnect: vi.fn(), onReconnect: vi.fn() };
  renderWithProviders(
    <ConnectionCard
      status={makeStatus(status)}
      profiles={[office, mdex]}
      {...handlers}
      {...props}
    />,
  );
  return handlers;
}

const connected: Partial<ConnectionStatus> = {
  state: 'connected',
  profileId: 'p2',
  profileName: 'mdex',
  protocol: 'openvpn',
  vpnIp: '10.8.0.6',
  remote: '203.0.113.7:1194',
  advisories: mdex.advisories,
};

afterEach(() => {
  vi.useRealTimers();
});

describe('ConnectionCard', () => {
  describe('IPsec', () => {
    const gateway = makeProfile({
      id: 'ip1',
      name: 'Head office',
      protocol: 'ipsec',
      settings: { gateway: 'vpn.example.com', ikeVersion: 'ikev1' },
      advisories: [{ code: 'ikev1_aggressive', severity: 'danger', field: 'ikeVersion' }],
    });
    const failed: Partial<ConnectionStatus> = {
      state: 'error',
      profileId: 'ip1',
      profileName: 'Head office',
      protocol: 'ipsec',
      advisories: gateway.advisories,
      lastError: {
        code: 'proposal_mismatch',
        message: 'NO_PROPOSAL_CHOSEN',
        time: '2026-11-26T10:00:00Z',
      },
    };

    it('names IPsec and the gateway host in the connection line', () => {
      renderCard({ ...failed, state: 'connecting', lastError: undefined }, { profiles: [gateway] });
      const line = screen.getByRole('group', { name: /Connecting/ });
      expect(line).toHaveTextContent('IPsec');
      expect(line).not.toHaveTextContent('IPsec/IKEv2');
      expect(line).toHaveTextContent('vpn.example.com');
    });

    it.each([
      ['proposal_mismatch', 'The gateway accepted none of the proposals'],
      ['ts_unacceptable', 'The gateway refused the subnets of the tunnel'],
      ['no_virtual_ip', 'The gateway assigned no virtual IP'],
      ['auth_failed', 'The server rejected the credentials'],
    ])('translates the error code %s', (code, text) => {
      renderCard(
        { ...failed, lastError: { code, message: code, time: '2026-11-26T10:00:00Z' } },
        { profiles: [gateway] },
      );
      expect(screen.getByText(text, { exact: false })).toBeInTheDocument();
    });

    it('shows the IKEv1 advisory as a danger', () => {
      renderCard(failed, { profiles: [gateway] });
      const advisory = screen.getByText(/IKEv1 is deprecated \(RFC 9395\)/).closest('li');
      expect(advisory).toHaveAttribute('data-severity', 'danger');
    });
  });

  describe('WireGuard', () => {
    const tunnel = makeProfile({
      id: 'wg1',
      name: 'Tunnel',
      protocol: 'wireguard',
      settings: { endpoint: 'wg.example.com:51820', address: '10.66.0.2/32' },
    });
    const connecting: Partial<ConnectionStatus> = {
      state: 'connecting',
      profileId: 'wg1',
      profileName: 'Tunnel',
      protocol: 'wireguard',
    };

    it('names the protocol and the endpoint host in the connection line', () => {
      renderCard(connecting, { profiles: [tunnel] });
      const line = screen.getByRole('group', { name: /Connecting/ });
      expect(line).toHaveTextContent('WireGuard');
      expect(line).toHaveTextContent('wg.example.com');
      expect(line).not.toHaveTextContent('51820');
    });

    it('shows the translated message code while connecting', () => {
      renderCard(
        { ...connecting, messageCode: 'wireguard_no_handshake', message: 'No answer (English)' },
        { profiles: [tunnel] },
      );
      expect(screen.getByRole('status')).toHaveTextContent(
        'No answer from the server – check the keys and the endpoint',
      );
      expect(screen.queryByText(/No answer (English)/)).not.toBeInTheDocument();
    });

    it('falls back to the message for an unknown code', () => {
      renderCard(
        { ...connecting, messageCode: 'future_code', message: 'Something new' },
        { profiles: [tunnel] },
      );
      expect(screen.getByRole('status')).toHaveTextContent('Something new');
    });

    it('drops the note once the tunnel is up', () => {
      renderCard(
        { ...connecting, state: 'connected', messageCode: 'wireguard_no_handshake' },
        { profiles: [tunnel] },
      );
      expect(screen.queryByText(/No answer from the server/)).not.toBeInTheDocument();
    });
  });

  it.each<[ConnectionState, string]>([
    ['disconnected', 'Disconnected'],
    ['connecting', 'Connecting'],
    ['reconnecting', 'Reconnecting'],
    ['disconnecting', 'Disconnecting'],
    ['connected', 'Connected'],
    ['error', 'Error'],
  ])('announces %s as "%s" in a hidden live region', (state, label) => {
    renderCard({ ...connected, state });
    const live = document.querySelector('[aria-live="polite"]');
    expect(live).toHaveClass('visually-hidden');
    expect(live).toHaveTextContent(label);
  });

  it('shows no state pill, profile name or protocol badge in the header', () => {
    renderCard(connected);
    expect(screen.queryByRole('heading', { name: 'Office' })).not.toBeInTheDocument();
    expect(screen.getAllByText('OpenVPN')).toHaveLength(1);
  });

  it('hands the actions to the details and puts the advisories in notices below them', () => {
    renderCard(connected, {
      details: (actions) => <aside aria-label="Details">{actions}</aside>,
    });
    const details = screen.getByRole('complementary', { name: 'Details' });
    expect(within(details).getByRole('button', { name: 'Disconnect' })).toBeInTheDocument();
    const notice = screen.getByText('Recommendations');
    expect(details.compareDocumentPosition(notice)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
    expect(document.querySelectorAll('[data-tone="danger"]')).toHaveLength(1);
    expect(screen.getByRole('list', { name: 'Advisories' }).closest('section')).toBeNull();
  });

  it('shows "cipher none" as a warning while the tunnel negotiated a cipher', () => {
    renderCard({ ...connected, dataCipher: 'CHACHA20-POLY1305' });
    const items = screen.getAllByRole('listitem');
    expect(items.map((item) => item.dataset.severity)).toEqual(['warning', 'warning', 'info']);
    expect(items[0]).toHaveTextContent('This connection negotiated a cipher and is encrypted');
  });

  it('places the actions below the connection line', () => {
    renderCard(connected);
    const line = document.querySelector('[data-link="tunnel"]');
    const disconnect = screen.getByRole('button', { name: 'Disconnect' });
    expect(line?.compareDocumentPosition(disconnect)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
  });

  it('offers a profile select and Connect when disconnected', () => {
    const { onConnect } = renderCard({ state: 'disconnected' });
    const select = screen.getByRole('combobox', { name: 'Profile' });

    fireEvent.change(select, { target: { value: 'p2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));

    expect(onConnect).toHaveBeenCalledWith('p2');
    expect(screen.getByText('publicip20.mdex.de')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Disconnect' })).not.toBeInTheDocument();
  });

  it('hides the select when there is only one profile', () => {
    renderCard({ state: 'disconnected' }, { profiles: [office] });
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect' })).toBeEnabled();
  });

  it('shows server, VPN IP, live duration and offers Reconnect and Disconnect when connected', () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    vi.setSystemTime(new Date('2026-11-25T13:12:00Z'));
    const { onReconnect, onDisconnect } = renderCard({
      ...connected,
      since: '2026-11-25T10:00:00Z',
    });

    expect(screen.getByText('publicip20.mdex.de')).toBeInTheDocument();
    expect(screen.getByText('10.8.0.6')).toBeInTheDocument();
    expect(screen.getByText('3 h 12 min')).toBeInTheDocument();
    expect(screen.getAllByText('OpenVPN')).toHaveLength(1);

    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(screen.getByText('3 h 13 min')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Reconnect' }));
    fireEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    expect(onReconnect).toHaveBeenCalled();
    expect(onDisconnect).toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Connect' })).not.toBeInTheDocument();
  });

  it.each([
    ['the detected public IP below the VPN IP', undefined, '46.16.217.194', '46.16.217.194'],
    [
      'the public address of the profile first',
      'vpn.mdex.example',
      '46.16.217.194',
      'vpn.mdex.example',
    ],
    ['a dash while neither is known', undefined, undefined, '–'],
  ])('shows %s in the connection line', (_case, publicAddress, publicIp, want) => {
    renderCard({ ...connected, publicIp }, { profiles: [office, { ...mdex, publicAddress }] });
    const publicLine = screen.getByText('Public IP:');
    expect(publicLine).toHaveTextContent(`Public IP: ${want}`);
    expect(screen.getByText('VPN IP:').nextElementSibling).toBe(publicLine);
  });

  it('offers Disconnect while connecting and shows no VPN IP or rates yet', () => {
    const { onDisconnect } = renderCard({
      state: 'connecting',
      profileId: 'p1',
      profileName: 'Office',
    });
    fireEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    expect(onDisconnect).toHaveBeenCalled();
    expect(screen.getByText('VPN IP:').parentElement).toHaveTextContent('VPN IP: –');
    expect(screen.getByText('Public IP:')).toHaveTextContent('Public IP: –');
    expect(screen.getByText('→ Received: –')).toBeInTheDocument();
    expect(screen.getByText('← Sent: –')).toBeInTheDocument();
  });

  it('shows a busy Disconnect while disconnecting', () => {
    renderCard({ state: 'disconnecting', profileId: 'p1' });
    const button = screen.getByRole('button', { name: 'Disconnect' });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('aria-busy', 'true');
  });

  it.each([
    ['auth_failed', 'The server rejected the credentials – AUTH_FAILED'],
    ['firewall_failed', 'The firewall rules could not be applied – AUTH_FAILED'],
    ['start_failed', 'The VPN process could not be started – AUTH_FAILED'],
    [
      'endpoint_in_tunnel',
      'The server address lies in a network routed through the tunnel – AUTH_FAILED',
    ],
    ['something_new', 'AUTH_FAILED'],
  ])('shows the error message with the translated code %s and Try again', (code, text) => {
    const { onConnect } = renderCard({
      state: 'error',
      profileId: 'p1',
      lastError: { code, message: 'AUTH_FAILED', time: '2026-11-25T10:00:00Z' },
    });
    expect(screen.getByText(text, { exact: false })).toHaveTextContent(
      `${text} Open log for details`,
    );
    expect(screen.getByRole('link', { name: 'Open log for details' })).toHaveAttribute(
      'href',
      '/log',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(onConnect).toHaveBeenCalledWith('p1');
  });

  it('lists the advisories of the active profile coloured by severity, danger first', () => {
    renderCard(connected);
    const items = screen.getAllByRole('listitem');
    expect(items.map((item) => item.dataset.severity)).toEqual(['danger', 'warning', 'info']);
    expect(items[0]).toHaveTextContent('The data channel uses no cipher');
  });

  it('shows the advisories of the selected profile while disconnected', () => {
    renderCard({ state: 'disconnected' });
    expect(screen.getAllByRole('listitem')).toHaveLength(1);
    fireEvent.change(screen.getByRole('combobox', { name: 'Profile' }), {
      target: { value: 'p2' },
    });
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
  });

  it('shows a failed action as an alert', () => {
    renderCard({ state: 'disconnected' }, { actionError: 'Something went wrong. Try again.' });
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong');
  });

  it('shows the LAN, firewall link, host address and version in the connection line', () => {
    renderCard(connected, { firewall: makeFirewall(), deviceCount: 4, version: '0.2.0' });
    const line = screen.getByRole('group');
    expect(line).toHaveAccessibleName(
      'Connected. VPN server publicip20.mdex.de, this device, local LAN 192.168.1.0/24 · 4 devices. Firewall: 1 rule, 0 forwards active.',
    );
    expect(screen.getByText('192.168.1.0/24 · 4 devices')).toBeInTheDocument();
    expect(screen.getByText('Firewall: 1 rule')).toBeInTheDocument();
    expect(screen.getByText('0 forwards active')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.10 · TunnelDeck-VPN 0.2.0')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open firewall' })).toHaveAttribute(
      'href',
      '/firewall',
    );
    expect(document.querySelector('[data-link="firewall"]')).toHaveAttribute(
      'data-tone',
      'success',
    );
  });

  it.each<[ConnectionState, string, string]>([
    ['disconnected', 'neutral', 'true'],
    ['connecting', 'warning', 'false'],
    ['connected', 'success', 'false'],
    ['error', 'danger', 'false'],
  ])('draws the tunnel link for %s as %s (dashed %s)', (state, tone, dashed) => {
    renderCard({ ...connected, state });
    const link = document.querySelector('[data-link="tunnel"]');
    expect(link).toHaveAttribute('data-tone', tone);
    expect(link).toHaveAttribute('data-dashed', dashed);
  });

  it('stacks the connection line vertically on narrow screens', () => {
    vi.stubGlobal(
      'matchMedia',
      vi.fn((query: string) => ({
        matches: true,
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      })),
    );
    renderCard(connected);
    expect(screen.getByRole('group')).toHaveAttribute('data-layout', 'vertical');
  });

  it('keeps the connection line horizontal without a narrow match', () => {
    renderCard(connected);
    expect(screen.getByRole('group')).toHaveAttribute('data-layout', 'horizontal');
  });

  it('shows a routing warning with a link to the log while the tunnel is up', () => {
    renderCard({
      ...connected,
      routingWarning: {
        code: 'routing_failed',
        message: 'applying the tunnel routing failed: ip rule add: exit status 2',
        time: '2026-11-25T10:00:00Z',
      },
    });
    const notice = screen.getByRole('status');
    expect(notice).toHaveTextContent(
      'Routing for forwarded traffic could not be applied; retrying…',
    );
    expect(screen.getByRole('link', { name: 'Open log for details' })).toHaveAttribute(
      'href',
      '/log',
    );
  });

  it('shows no routing warning without one', () => {
    renderCard(connected);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
});
