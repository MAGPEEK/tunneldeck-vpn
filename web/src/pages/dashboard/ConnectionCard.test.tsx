import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ConnectionState, ConnectionStatus } from '../../api/connection';
import { makeProfile, makeStatus } from '../../test/fixtures';
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
  render(
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
  it.each<[ConnectionState, string, string]>([
    ['disconnected', 'Disconnected', 'neutral'],
    ['connecting', 'Connecting', 'warning'],
    ['reconnecting', 'Reconnecting', 'warning'],
    ['disconnecting', 'Disconnecting', 'warning'],
    ['connected', 'Connected', 'success'],
    ['error', 'Error', 'danger'],
  ])('shows %s as "%s" in a %s pill inside a live region', (state, label, tone) => {
    renderCard({ ...connected, state });
    const pill = screen.getByText(label);
    expect(pill.closest('[data-tone]')).toHaveAttribute('data-tone', tone);
    expect(pill.closest('[aria-live]')).toHaveAttribute('aria-live', 'polite');
  });

  it('offers a profile select and Connect when disconnected', () => {
    const { onConnect } = renderCard({ state: 'disconnected' });
    const select = screen.getByRole('combobox', { name: 'Profile' });
    expect(screen.getByRole('heading', { name: 'Office' })).toBeInTheDocument();

    fireEvent.change(select, { target: { value: 'p2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));

    expect(onConnect).toHaveBeenCalledWith('p2');
    expect(screen.getByText('publicip20.mdex.de:1194')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Disconnect' })).not.toBeInTheDocument();
  });

  it('hides the select when there is only one profile', () => {
    renderCard({ state: 'disconnected' }, { profiles: [office] });
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect' })).toBeEnabled();
  });

  it('shows server, VPN address, live duration and offers Reconnect and Disconnect when connected', () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    vi.setSystemTime(new Date('2026-11-25T13:12:00Z'));
    const { onReconnect, onDisconnect } = renderCard({
      ...connected,
      since: '2026-11-25T10:00:00Z',
    });

    expect(screen.getByText('203.0.113.7:1194')).toBeInTheDocument();
    expect(screen.getByText('10.8.0.6')).toBeInTheDocument();
    expect(screen.getByText('3 h 12 min')).toBeInTheDocument();
    expect(screen.getByText('OpenVPN')).toBeInTheDocument();

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

  it('offers Disconnect while connecting and shows dashes for missing values', () => {
    const { onDisconnect } = renderCard({
      state: 'connecting',
      profileId: 'p1',
      profileName: 'Office',
    });
    fireEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    expect(onDisconnect).toHaveBeenCalled();
    expect(screen.getAllByText('–')).toHaveLength(2);
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
    ['something_new', 'AUTH_FAILED'],
  ])('shows the error message with the translated code %s and Try again', (code, text) => {
    const { onConnect } = renderCard({
      state: 'error',
      profileId: 'p1',
      lastError: { code, message: 'AUTH_FAILED', time: '2026-11-25T10:00:00Z' },
    });
    expect(screen.getByText(text)).toBeInTheDocument();
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
});
