import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import { Button } from '../../components/Button';
import { Field } from '../../components/Field';
import { AuthLayout } from '../../layout/AuthLayout';
import styles from '../../layout/AuthLayout.module.css';
import { useSetup } from '../../session/useSession';
import { genericErrorMessage } from '../auth/formError';
import { USERNAME_MAX, validateSetup, type SetupErrors, type SetupValues } from './validateSetup';

const EMPTY: SetupValues = { username: '', password: '', repeatPassword: '' };

export function SetupPage() {
  const { t } = useTranslation();
  const setup = useSetup();
  const [values, setValues] = useState<SetupValues>(EMPTY);
  const [errors, setErrors] = useState<SetupErrors>({});

  const serverFields = isApiError(setup.error) ? setup.error.fields : {};
  const hasServerFieldErrors = Object.keys(serverFields).length > 0;
  const fieldError = (name: keyof SetupValues) => {
    const key = errors[name];
    return key ? t(key) : serverFields[name];
  };
  const update = (name: keyof SetupValues) => (event: FormEvent<HTMLInputElement>) =>
    setValues({ ...values, [name]: event.currentTarget.value });

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const found = validateSetup(values);
    setErrors(found);
    if (Object.keys(found).length === 0) {
      setup.mutate({ username: values.username.trim(), password: values.password });
    }
  };

  return (
    <AuthLayout title={t('setup.title')}>
      <form className={styles.form} onSubmit={submit} noValidate>
        <Field
          label={t('auth.username')}
          hint={t('setup.usernameHint')}
          error={fieldError('username')}
          name="username"
          autoComplete="username"
          maxLength={USERNAME_MAX}
          value={values.username}
          onChange={update('username')}
        />
        <Field
          label={t('auth.password')}
          hint={t('setup.passwordHint')}
          error={fieldError('password')}
          name="password"
          type="password"
          autoComplete="new-password"
          value={values.password}
          onChange={update('password')}
        />
        <Field
          label={t('setup.repeatPassword')}
          error={fieldError('repeatPassword')}
          name="repeatPassword"
          type="password"
          autoComplete="new-password"
          value={values.repeatPassword}
          onChange={update('repeatPassword')}
        />
        {setup.isError && !hasServerFieldErrors && (
          <p role="alert" className={styles.formError}>
            {genericErrorMessage(t, setup.error)}
          </p>
        )}
        <Button type="submit" variant="primary" loading={setup.isPending}>
          {t('setup.submit')}
        </Button>
      </form>
    </AuthLayout>
  );
}
