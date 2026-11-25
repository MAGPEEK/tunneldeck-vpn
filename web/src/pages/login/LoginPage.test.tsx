import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { problem, type MockReply } from '../../test/fetchMock';
import { SIGNED_IN, SIGNED_OUT, renderApp } from '../../test/renderApp';

async function signIn(loginReply: MockReply) {
  const rendered = renderApp({
    'GET /api/session': [{ body: SIGNED_OUT }, { body: SIGNED_IN }],
    'POST /api/login': loginReply,
  });
  await screen.findByRole('heading', { name: 'Sign in' });
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'secret' } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  return rendered;
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
});
