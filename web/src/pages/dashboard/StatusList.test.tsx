import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ConnectionStatus } from '../../api/connection';
import type { RemoteAccess } from '../../api/remoteAccess';
import { makeFirewall, makeRule, makeStatus } from '../../test/fixtures';
import { DASHBOARD_STORAGE_KEY, useDashboardItems } from './dashboardItems';
import { StatusList, type StatusListProps } from './StatusList';

const connected = makeStatus({
  state: 'connected',
  vpnIp: '10.8.0.6',
  remote: '203.0.113.7:1194',
  since: '2026-11-25T10:00:00Z',
  bytesIn: 2_500_000,
  bytesOut: 1000,
  rateIn: 125_000,
  rateOut: 0,
});

const remoteOn: RemoteAccess = {
  enabled: true,
  port: 8443,
  certificateSource: 'selfSigned',
  certificate: null,
  listening: true,
};

type HarnessProps = { status: ConnectionStatus } & Partial<Omit<StatusListProps, 'items'>>;

function Harness({ status, ...props }: HarnessProps) {
  const items = useDashboardItems();
  return (
    <StatusList
      status={status}
      server="vpn.example.com:1194"
      firewall={makeFirewall()}
      deviceCount={3}
      remoteAccess={null}
      items={items}
      {...props}
    />
  );
}

function renderList(status: ConnectionStatus, props: Partial<Omit<StatusListProps, 'items'>> = {}) {
  return render(<Harness status={status} {...props} />);
}

function row(id: string): HTMLElement {
  const element = document.querySelector<HTMLElement>(`[data-row="${id}"]`);
  if (element === null) {
    throw new Error(`row ${id} not found`);
  }
  return element;
}

function rowIds(): (string | undefined)[] {
  return Array.from(document.querySelectorAll<HTMLElement>('[data-row]')).map(
    (element) => element.dataset.row,
  );
}

describe('StatusList', () => {
  it('lists tunnel, address, LAN, firewall and traffic with status dots and text', () => {
    renderList(connected);

    expect(screen.getByRole('heading', { name: 'Connection details' })).toBeInTheDocument();
    expect(rowIds()).toEqual(['tunnel', 'address', 'lan', 'firewall', 'traffic']);
    expect(row('tunnel')).toHaveAttribute('data-tone', 'success');
    expect(within(row('tunnel')).getByText('VPN tunnel')).toHaveTextContent(
      'VPN tunnel (status OK)',
    );
    expect(row('tunnel')).toHaveTextContent('↓ 1.0 Mbit/s');
    expect(row('tunnel')).toHaveTextContent('↑ 0 bit/s');
    expect(within(row('address')).getByText(/^Connected since /)).toBeInTheDocument();
    expect(within(row('address')).getByText('10.8.0.6')).toBeInTheDocument();
    expect(within(row('address')).getByText('203.0.113.7:1194')).toBeInTheDocument();
    expect(within(row('lan')).getByText('192.168.1.10')).toBeInTheDocument();
    expect(within(row('lan')).getByText('192.168.1.0/24')).toBeInTheDocument();
    expect(within(row('lan')).getByText('3 devices')).toBeInTheDocument();
    expect(row('firewall')).toHaveTextContent('1 active rule');
    expect(row('firewall')).toHaveTextContent('0 forwards active');
    expect(row('firewall')).toHaveTextContent('All protections active');
    expect(row('traffic')).toHaveTextContent('Received 2.5 MB');
    expect(row('traffic')).toHaveTextContent('Sent 1.0 kB');
  });

  it('shows dashes and the configured server while disconnected', () => {
    renderList(makeStatus());
    expect(row('tunnel')).toHaveAttribute('data-tone', 'neutral');
    expect(row('tunnel')).toHaveTextContent('Disconnected');
    expect(row('address')).toHaveTextContent('Not connected');
    expect(within(row('address')).getByText('vpn.example.com:1194')).toBeInTheDocument();
    expect(row('traffic')).toHaveTextContent('Received –');
  });

  it('shows the encryption row when the server reports ciphers', () => {
    renderList({
      ...connected,
      dataCipher: 'CHACHA20-POLY1305',
      controlChannel: 'TLSv1.3 TLS_CHACHA20_POLY1305_SHA256',
    });
    expect(rowIds()).toContain('encryption');
    expect(row('encryption')).toHaveAttribute('data-tone', 'success');
    expect(row('encryption')).toHaveTextContent('Data channel CHACHA20-POLY1305');
    expect(row('encryption')).toHaveTextContent(
      'Control channel TLSv1.3 TLS_CHACHA20_POLY1305_SHA256',
    );
  });

  it('marks an unencrypted data channel as a problem', () => {
    renderList({ ...connected, dataCipher: 'none' });
    expect(row('encryption')).toHaveAttribute('data-tone', 'danger');
    expect(row('encryption')).toHaveTextContent('Data channel not encrypted');
    expect(row('encryption')).toHaveTextContent('Encryption (status problem)');
  });

  it('warns about limited protections and IP forwarding', () => {
    renderList(connected, {
      firewall: makeFirewall({
        rules: [makeRule({ destination: '192.168.1.20' })],
        ipForward: false,
        protectionsAvailable: {
          synFlood: 'global',
          ping: 'full',
          mssClamp: 'full',
          ruleCounters: true,
        },
      }),
    });
    expect(row('firewall')).toHaveAttribute('data-tone', 'warning');
    expect(row('firewall')).toHaveTextContent('1 forward active');
    expect(row('firewall')).toHaveTextContent('Some protections limited on this system');
    expect(row('firewall')).toHaveTextContent('IP forwarding is off on the host');
  });

  it.each<[RemoteAccess, string, string]>([
    [remoteOn, 'success', 'https://10.8.0.6:8443'],
    [{ ...remoteOn, listening: false }, 'warning', 'HTTPS on port 8443'],
    [{ ...remoteOn, enabled: false }, 'neutral', 'Off'],
  ])('shows remote access %#', (remoteAccess, tone, text) => {
    renderList(connected, { remoteAccess });
    expect(row('remote')).toHaveAttribute('data-tone', tone);
    expect(row('remote')).toHaveTextContent(text);
  });

  it('links remote access at the public address with a Copy button', () => {
    renderList(connected, { remoteAccess: remoteOn, publicAddress: 'vpn.example.com' });
    const link = within(row('remote')).getByRole('link', { name: 'https://vpn.example.com:8443' });
    expect(link).toHaveAttribute('href', 'https://vpn.example.com:8443');
    expect(within(row('remote')).getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(row('remote')).not.toHaveTextContent('Set the public address');
  });

  it('falls back to the VPN IP with a hint when the profile names no public address', () => {
    renderList(connected, { remoteAccess: remoteOn, publicAddress: '' });
    expect(
      within(row('remote')).getByRole('link', { name: 'https://10.8.0.6:8443' }),
    ).toBeInTheDocument();
    expect(row('remote')).toHaveTextContent(
      'Set the public address in the profile if your provider uses a different one.',
    );
  });

  it('shows the port while the tunnel is down and the last error while not listening', () => {
    const { unmount } = renderList(makeStatus(), { remoteAccess: remoteOn });
    expect(row('remote')).toHaveTextContent('HTTPS on port 8443');
    expect(within(row('remote')).queryByRole('link')).not.toBeInTheDocument();
    unmount();
    renderList(connected, {
      remoteAccess: { ...remoteOn, listening: false, lastError: 'address already in use' },
    });
    expect(row('remote')).toHaveAttribute('data-tone', 'warning');
    expect(row('remote')).toHaveTextContent('Last error: address already in use');
  });

  it('hides remote access when the build has none and the device count while unknown', () => {
    renderList(connected, { remoteAccess: null, deviceCount: undefined });
    expect(rowIds()).not.toContain('remote');
    expect(row('lan')).not.toHaveTextContent('devices');
  });

  it('hides and shows rows from the customize checklist and remembers the choice', () => {
    const { unmount } = renderList(connected);
    const toggle = screen.getByRole('button', { name: 'Customize' });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    const checklist = screen.getByRole('group', { name: 'Show on the dashboard' });
    expect(within(checklist).getAllByRole('checkbox')).toHaveLength(8);
    expect(
      within(checklist)
        .getAllByRole('checkbox')
        .every((box) => (box as HTMLInputElement).checked),
    ).toBe(true);

    fireEvent.click(within(checklist).getByRole('checkbox', { name: 'Firewall' }));
    expect(rowIds()).not.toContain('firewall');
    expect(JSON.parse(localStorage.getItem(DASHBOARD_STORAGE_KEY) ?? '[]')).toEqual(['firewall']);

    unmount();
    renderList(connected);
    expect(rowIds()).toEqual(['tunnel', 'address', 'lan', 'traffic']);
  });

  it('hides a row directly with its hide button', () => {
    renderList(connected);
    fireEvent.click(screen.getByRole('button', { name: 'Hide Traffic total' }));
    expect(rowIds()).not.toContain('traffic');
    fireEvent.click(screen.getByRole('button', { name: 'Customize' }));
    expect(screen.getByRole('checkbox', { name: 'Traffic total' })).not.toBeChecked();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Traffic total' }));
    expect(rowIds()).toContain('traffic');
  });

  it('restores all rows with Reset', () => {
    localStorage.setItem(DASHBOARD_STORAGE_KEY, JSON.stringify(['tunnel', 'lan', 'unknown']));
    renderList(connected);
    expect(rowIds()).toEqual(['address', 'firewall', 'traffic']);
    fireEvent.click(screen.getByRole('button', { name: 'Customize' }));
    fireEvent.click(screen.getByRole('button', { name: 'Reset' }));
    expect(rowIds()).toEqual(['tunnel', 'address', 'lan', 'firewall', 'traffic']);
    expect(localStorage.getItem(DASHBOARD_STORAGE_KEY)).toBeNull();
  });

  it('ignores a broken stored choice', () => {
    localStorage.setItem(DASHBOARD_STORAGE_KEY, '{nope');
    renderList(connected);
    expect(rowIds()).toHaveLength(5);
  });
});
