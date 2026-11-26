import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
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

describe('LoginPage', () => {
  it('shows a generic message for wrong credentials', async () => {
    await signIn(problem(401, 'invalid_credentials', 'bad login'));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Username or password is incorrect.',
    );
  });

  it('shows the wait time when rate limited', async () => {
    await signIn(
      problem(429, 'rate_limited', 'too many attempts', { headers: { 'Retry-After': '45' } }),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Too many failed attempts. Try again in 45 seconds.',
    );
  });

  it('falls back to a later hint when no wait time is given', async () => {
    await signIn(problem(429, 'rate_limited', 'too many attempts'));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Too many failed attempts. Try again later.',
    );
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
