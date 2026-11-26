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

function loginErrorMessage(t: TFunction, error: unknown): string {
  if (isApiError(error) && error.status === 401) {
    return t('login.invalidCredentials');
  }
  if (isApiError(error) && error.status === 429) {
    return error.retryAfterSeconds === undefined
      ? t('login.rateLimitedLater')
      : t('login.rateLimited', { count: error.retryAfterSeconds });
  }
  return genericErrorMessage(t, error);
}

/** rememberAvailable offers "Stay signed in" (LAN listener only). */
export function LoginPage({ rememberAvailable }: { rememberAvailable: boolean }) {
  const { t } = useTranslation();
  const login = useLogin();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    login.mutate({
      username: username.trim(),
      password,
      ...(rememberAvailable && { remember }),
    });
  };

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
          <p role="alert" className={styles.formError}>
            {loginErrorMessage(t, login.error)}
          </p>
        )}
        <Button type="submit" variant="primary" loading={login.isPending}>
          {t('login.submit')}
        </Button>
      </form>
    </AuthLayout>
  );
}
