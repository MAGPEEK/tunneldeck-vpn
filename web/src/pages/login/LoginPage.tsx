import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { isApiError } from '../../api/client';
import { Button } from '../../components/Button';
import { Field } from '../../components/Field';
import { AuthLayout } from '../../layout/AuthLayout';
import styles from '../../layout/AuthLayout.module.css';
import { useLogin } from '../../session/useSession';
import { genericErrorMessage } from '../auth/formError';
import { useCountdown } from './useCountdown';

/** Why sign-in has to wait: a wrong password, the client's own cooldown or
 * the remote listener's lock for everyone (SPEC §8, §8.1). */
type WaitReason = 'credentials' | 'client' | 'remote';

function waitReason(error: unknown): WaitReason | undefined {
  if (!isApiError(error)) {
    return undefined;
  }
  if (error.status === 401) {
    return 'credentials';
  }
  if (error.status === 429) {
    return error.code === 'rate_limited_remote' ? 'remote' : 'client';
  }
  return undefined;
}

/** The seconds the server asks to wait after error, 0 for none. */
function waitSeconds(error: unknown): number {
  return isApiError(error) && waitReason(error) !== undefined ? (error.retryAfterSeconds ?? 0) : 0;
}

function waitingMessage(t: TFunction, reason: WaitReason, seconds: number): string {
  switch (reason) {
    case 'credentials':
      return t('login.invalidCredentialsWait', { count: seconds });
    case 'client':
      return t('login.rateLimited', { count: seconds });
    case 'remote':
      return t('login.rateLimitedRemote', { count: seconds });
  }
}

/** The message while no wait is running; waitStarted tells whether one ran. */
function settledMessage(t: TFunction, error: unknown, waitStarted: boolean): string {
  switch (waitReason(error)) {
    case 'credentials':
      return t('login.invalidCredentials');
    case 'client':
      return waitStarted ? t('login.waitOver') : t('login.rateLimitedLater');
    case 'remote':
      return waitStarted ? t('login.waitOver') : t('login.rateLimitedRemoteLater');
    default:
      return genericErrorMessage(t, error);
  }
}

/** rememberAvailable offers "Stay signed in" (LAN listener only). */
export function LoginPage({ rememberAvailable }: { rememberAvailable: boolean }) {
  const { t } = useTranslation();
  const login = useLogin();
  const countdown = useCountdown();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    login.mutate(
      {
        username: username.trim(),
        password,
        ...(rememberAvailable && { remember }),
      },
      { onError: (error) => countdown.start(waitSeconds(error)) },
    );
  };

  const reason = waitReason(login.error);
  const waitStarted = login.isError && reason !== undefined && countdown.started > 0;
  const waiting = waitStarted && countdown.remaining > 0;
  // The live region speaks only when a wait starts and when it ends, not
  // on every tick of the visible countdown.
  let announcement = '';
  if (waiting && reason !== undefined) {
    announcement = waitingMessage(t, reason, countdown.started);
  } else if (waitStarted) {
    announcement = t('login.waitOver');
  }

  return (
    <AuthLayout title={t('login.title')}>
      <form className={styles.form} onSubmit={submit}>
        <Field
          label={t('auth.username')}
          name="username"
          autoComplete="username"
          required
          value={username}
          onChange={(event) => setUsername(event.currentTarget.value)}
        />
        <Field
          label={t('auth.password')}
          name="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.currentTarget.value)}
        />
        {rememberAvailable && (
          <label className={styles.checkbox}>
            <input
              type="checkbox"
              name="remember"
              checked={remember}
              onChange={(event) => setRemember(event.currentTarget.checked)}
            />
            {t('login.remember')}
          </label>
        )}
        {login.isError && (
          <p role={waitStarted ? undefined : 'alert'} className={styles.formError}>
            {waiting && reason !== undefined
              ? waitingMessage(t, reason, countdown.remaining)
              : settledMessage(t, login.error, waitStarted)}
          </p>
        )}
        <p className="visually-hidden" aria-live="polite" aria-atomic="true">
          {announcement}
        </p>
        <Button type="submit" variant="primary" loading={login.isPending} disabled={waiting}>
          {t('login.submit')}
        </Button>
      </form>
    </AuthLayout>
  );
}
