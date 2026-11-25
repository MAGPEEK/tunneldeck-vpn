import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { problem } from '../../test/fetchMock';
import { NEEDS_SETUP, SIGNED_OUT, renderApp } from '../../test/renderApp';

function fill(username: string, password: string, repeatPassword: string) {
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: username } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } });
  fireEvent.change(screen.getByLabelText('Repeat password'), {
    target: { value: repeatPassword },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Create account' }));
}

describe('SetupPage', () => {
  it('validates the fields before sending anything', async () => {
    const { fetchMock } = renderApp({ 'GET /api/session': { body: NEEDS_SETUP } });
    await screen.findByRole('heading', { name: 'Create the admin account' });

    fill('ab', 'short', 'different');

    expect(screen.getByLabelText('Username')).toHaveAccessibleDescription(
      '3 to 32 characters Use 3 to 32 characters.',
    );
    expect(screen.getByLabelText('Password')).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByText('Use at least 12 characters.')).toBeInTheDocument();
    expect(screen.getByLabelText('Repeat password')).toHaveAccessibleDescription(
      'The passwords do not match.',
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('shows server field errors under the matching field', async () => {
    renderApp({
      'GET /api/session': { body: NEEDS_SETUP },
      'POST /api/setup': problem(400, 'validation_failed', 'invalid input', {
        fields: { username: 'This username is reserved.' },
      }),
    });
    await screen.findByRole('heading', { name: 'Create the admin account' });

    fill('root', 'correct horse battery', 'correct horse battery');

    expect(await screen.findByText('This username is reserved.')).toBeInTheDocument();
    expect(screen.getByLabelText('Username')).toHaveAttribute('aria-invalid', 'true');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('sends the account and re-reads the session on success', async () => {
    const { fetchMock } = renderApp({
      'GET /api/session': [{ body: NEEDS_SETUP }, { body: SIGNED_OUT }],
      'POST /api/setup': { status: 204 },
    });
    await screen.findByRole('heading', { name: 'Create the admin account' });

    fill(' admin ', 'correct horse battery', 'correct horse battery');

    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/setup',
      expect.objectContaining({
        body: JSON.stringify({ username: 'admin', password: 'correct horse battery' }),
      }),
    );
  });
});
