import { act, fireEvent, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { getSystem } from './api/system';
import { problem } from './test/fetchMock';
import { NEEDS_SETUP, SIGNED_IN, SIGNED_OUT, renderApp } from './test/renderApp';
import { THEME_STORAGE_KEY } from './theme/theme';

describe('session routing', () => {
  it('shows setup when no admin exists', async () => {
    renderApp({ 'GET /api/session': { body: NEEDS_SETUP } });
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Create the admin account' }),
    ).toBeInTheDocument();
  });

  it('shows login when not authenticated', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_OUT } });
    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument();
  });

  it('shows the app shell with the page for the current path', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } }, '/profiles');
    expect(await screen.findByRole('heading', { level: 1, name: 'Profiles' })).toBeInTheDocument();
    const nav = screen.getByRole('navigation', { name: 'Main navigation' });
    expect(within(nav).getByRole('link', { name: 'Profiles' })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it('navigates between pages from the sidebar', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } });
    await screen.findByRole('heading', { level: 1, name: 'Dashboard' });

    fireEvent.click(screen.getByRole('link', { name: 'Firewall' }));

    expect(screen.getByRole('heading', { level: 1, name: 'Firewall' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/firewall');
  });

  it('lists the log between firewall and system and opens the log page', async () => {
    renderApp({
      'GET /api/session': { body: SIGNED_IN },
      'GET /api/logs?tail=2000': {
        body: {
          lines: [{ time: '2026-11-25T10:00:00Z', level: 'info', text: 'TunnelDeck started' }],
        },
      },
    });
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' });
    const names = within(nav)
      .getAllByRole('link')
      .map((link) => link.textContent);
    expect(names).toEqual(['Dashboard', 'Profiles', 'Firewall', 'Log', 'System', 'Help']);

    fireEvent.click(within(nav).getByRole('link', { name: 'Log' }));

    expect(screen.getByRole('heading', { level: 1, name: 'Log' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/log');
    expect(await screen.findByText('TunnelDeck started')).toBeInTheDocument();
  });

  it('lists help last and opens the help page', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } });
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' });

    fireEvent.click(within(nav).getByRole('link', { name: 'Help' }));

    expect(await screen.findByRole('heading', { level: 1, name: 'Help' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/help');
    expect(within(nav).getByRole('link', { name: 'Help' })).toHaveAttribute('aria-current', 'page');
  });

  it('redirects the old host-access path to the firewall', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } }, '/host-access');
    expect(await screen.findByRole('heading', { level: 1, name: 'Firewall' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/firewall');
  });

  it('redirects unknown paths to the dashboard', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } }, '/nope');
    expect(await screen.findByRole('heading', { level: 1, name: 'Dashboard' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/');
  });

  it('shows a retryable unreachable state when the session request fails', async () => {
    const { fetchMock } = renderApp({
      'GET /api/session': ['network-error', { body: SIGNED_OUT }],
    });

    expect(await screen.findByRole('heading', { name: "Can't reach the server" })).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));

    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('returns to login when an API call answers 401 mid-session', async () => {
    const { queryClient } = renderApp({
      'GET /api/session': { body: SIGNED_IN },
      'GET /api/system': problem(401, 'unauthorized', 'session expired'),
    });
    await screen.findByRole('heading', { level: 1, name: 'Dashboard' });

    await act(() =>
      queryClient.fetchQuery({ queryKey: ['system'], queryFn: getSystem }).catch(() => undefined),
    );

    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument();
  });

  it('signs out and shows login', async () => {
    const { fetchMock } = renderApp({
      'GET /api/session': { body: SIGNED_IN },
      'POST /api/logout': { status: 204 },
    });
    await screen.findByRole('heading', { level: 1, name: 'Dashboard' });

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));

    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/logout', expect.anything());
  });
});

describe('shell preferences', () => {
  it('cycles the theme, sets data-theme and persists the choice', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } });
    const toggle = await screen.findByRole('button', { name: 'Change theme (current: system)' });
    expect(document.documentElement).not.toHaveAttribute('data-theme');

    fireEvent.click(toggle);
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');

    fireEvent.click(screen.getByRole('button', { name: 'Change theme (current: light)' }));
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');

    fireEvent.click(screen.getByRole('button', { name: 'Change theme (current: dark)' }));
    expect(document.documentElement).not.toHaveAttribute('data-theme');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('system');
  });

  it('restores the stored theme for the toggle label', async () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'dark');
    renderApp({ 'GET /api/session': { body: SIGNED_IN } });
    expect(
      await screen.findByRole('button', { name: 'Change theme (current: dark)' }),
    ).toBeInTheDocument();
  });

  it('switches the language of visible text and remembers it', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } });
    await screen.findByRole('heading', { level: 1, name: 'Dashboard' });
    const group = screen.getByRole('group', { name: 'Language' });

    fireEvent.click(within(group).getByRole('button', { name: 'DE' }));

    expect(await screen.findByRole('heading', { level: 1, name: 'Übersicht' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Abmelden' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'DE' })).toHaveAttribute('aria-pressed', 'true');
    expect(localStorage.getItem('tunneldeck.language')).toBe('de');
    expect(document.documentElement.lang).toBe('de');
  });
});
