import { act, fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { problem, type MockReply } from '../../test/fetchMock';
import { SIGNED_IN, SIGNED_OUT, renderApp } from '../../test/renderApp';

async function signIn(loginReply: MockReply, session = SIGNED_OUT, remember = false) {
  const rendered = renderApp({
    'GET /api/session': [{ body: session }, { body: SIGNED_IN }],
    'POST /api/login': loginReply,
  });
  await screen.findByRole('heading', { name: 'Sign in' });
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'secret' } });
  if (remember) {
    fireEvent.click(screen.getByRole('checkbox', { name: 'Stay signed in' }));
  }
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  return rendered;
}

function loginBody(fetchMock: ReturnType<typeof renderApp>['fetchMock']) {
  const call = fetchMock.mock.calls.find(([url]) => url === '/api/login');
  return JSON.parse(String(call?.[1]?.body)) as Record<string, unknown>;
}

function liveRegion() {
  return document.querySelector('[aria-live="polite"]');
}

function tick(seconds: number) {
  act(() => {
    vi.advanceTimersByTime(seconds * 1000);
  });
}

describe('LoginPage', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows a generic message for wrong credentials without a cooldown', async () => {
    await signIn(problem(401, 'invalid_credentials', 'bad login'));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Username or password is incorrect.',
    );
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
  });

  it('counts the cooldown down right after a failed login and then re-enables sign-in', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    await signIn(
      problem(401, 'invalid_credentials', 'bad login', { headers: { 'Retry-After': '10' } }),
    );
    const start = 'Wrong username or password. You can sign in again in 10 seconds.';
    expect(await screen.findByText(start, { selector: 'p:not([aria-live])' })).toBeInTheDocument();
    const button = screen.getByRole('button', { name: 'Sign in' });
    expect(button).toBeDisabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(liveRegion()).toHaveClass('visually-hidden');
    expect(liveRegion()).toHaveTextContent(start);

    tick(1);
    expect(
      screen.getByText('Wrong username or password. You can sign in again in 9 seconds.'),
    ).toBeInTheDocument();
    expect(liveRegion()).toHaveTextContent(start);
    tick(8);
    expect(
      screen.getByText('Wrong username or password. You can sign in again in 1 second.'),
    ).toBeInTheDocument();
    expect(button).toBeDisabled();

    tick(1);
    expect(button).toBeEnabled();
    expect(screen.getByText('Username or password is incorrect.')).toBeInTheDocument();
    expect(liveRegion()).toHaveTextContent('You can sign in again now.');
  });

  it('counts down the wait when rate limited', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    await signIn(
      problem(429, 'rate_limited', 'too many attempts', { headers: { 'Retry-After': '45' } }),
    );
    expect(
      await screen.findByText('Too many failed attempts. Please wait 45 more seconds.', {
        selector: 'p:not([aria-live])',
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeDisabled();
    tick(44);
    expect(
      screen.getByText('Too many failed attempts. Please wait 1 more second.'),
    ).toBeInTheDocument();
    tick(1);
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
    expect(liveRegion()).toHaveTextContent('You can sign in again now.');
  });

  it('says when remote sign-in is blocked for everyone', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    await signIn(
      problem(429, 'rate_limited_remote', 'remote locked', { headers: { 'Retry-After': '60' } }),
    );
    const start =
      'Remote sign-in is temporarily blocked for everyone after too many failed attempts. Please wait 60 more seconds.';
    expect(await screen.findByText(start, { selector: 'p:not([aria-live])' })).toBeInTheDocument();
    expect(liveRegion()).toHaveTextContent(start);
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeDisabled();
  });

  it.each([
    ['rate_limited', 'Too many failed attempts. Try again later.'],
    [
      'rate_limited_remote',
      'Remote sign-in is temporarily blocked for everyone after too many failed attempts. Try again later.',
    ],
  ])('falls back to a later hint for %s without a wait time', async (code, message) => {
    await signIn(problem(429, code, 'too many attempts'));
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
  });

  it('opens the app after a successful login', async () => {
    await signIn({ status: 204 });
    expect(await screen.findByRole('heading', { level: 1, name: 'Dashboard' })).toBeInTheDocument();
  });

  it('offers "Stay signed in", unticked, where the server allows it', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_OUT } });
    const checkbox = await screen.findByRole('checkbox', { name: 'Stay signed in' });
    expect(checkbox).not.toBeChecked();
  });

  it('hides "Stay signed in" where the server does not allow it', async () => {
    renderApp({ 'GET /api/session': { body: { ...SIGNED_OUT, rememberAvailable: false } } });
    await screen.findByRole('heading', { name: 'Sign in' });
    expect(screen.queryByRole('checkbox', { name: 'Stay signed in' })).not.toBeInTheDocument();
  });

  it.each([
    { ticked: true, want: { username: 'admin', password: 'secret', remember: true } },
    { ticked: false, want: { username: 'admin', password: 'secret', remember: false } },
  ])('sends remember: $ticked from the checkbox', async ({ ticked, want }) => {
    const { fetchMock } = await signIn({ status: 204 }, SIGNED_OUT, ticked);
    await screen.findByRole('heading', { level: 1, name: 'Dashboard' });
    expect(loginBody(fetchMock)).toEqual(want);
  });

  it('sends no remember flag where it is not offered', async () => {
    const { fetchMock } = await signIn(
      { status: 204 },
      { ...SIGNED_OUT, rememberAvailable: false },
    );
    await screen.findByRole('heading', { level: 1, name: 'Dashboard' });
    expect(loginBody(fetchMock)).toEqual({ username: 'admin', password: 'secret' });
  });
});
