import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import { localizedFieldErrors } from '../../api/fieldErrors';
import { putPublicIpLookup, type PublicIpLookup } from '../../api/publicIpLookup';
import { queryKeys } from '../../api/queryKeys';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Field } from '../../components/Field';
import { Notice } from '../../components/Notice';
import { usePublicIpLookup } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { CheckboxField } from '../profiles/schema/CheckboxField';
import styles from './SystemPage.module.css';

/** SPEC §6.1: detection of the public IP the internet sees through the tunnel. */
export function PublicIpLookupCard() {
  const { t } = useTranslation();
  const lookup = usePublicIpLookup();
  return (
    <Card title={t('publicIpLookup.title')}>
      {lookup.isPending && <p aria-busy="true">{t('session.loading')}</p>}
      {lookup.isError && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, lookup.error)}
        </Notice>
      )}
      {lookup.data && <PublicIpLookupForm saved={lookup.data} />}
    </Card>
  );
}

function PublicIpLookupForm({ saved }: { saved: PublicIpLookup }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [draft, setDraft] = useState(saved);
  const save = useMutation({
    mutationFn: putPublicIpLookup,
    onSuccess: (result) => {
      client.setQueryData(queryKeys.publicIpLookup, result);
      setDraft(result);
    },
  });
  const dirty = draft.enabled !== saved.enabled || draft.url !== saved.url;
  const fields = isApiError(save.error) ? localizedFieldErrors(t, save.error) : {};

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    save.mutate(draft);
  };

  return (
    <form className={styles.form} onSubmit={submit}>
      <p className={styles.secondary}>{t('publicIpLookup.description')}</p>
      <CheckboxField
        label={t('publicIpLookup.enable')}
        checked={draft.enabled}
        error={fields.enabled}
        onChange={(enabled) => setDraft({ ...draft, enabled })}
      />
      <Field
        label={t('publicIpLookup.url')}
        type="text"
        inputMode="url"
        spellCheck={false}
        autoComplete="off"
        value={draft.url}
        hint={t('publicIpLookup.urlHint')}
        error={fields.url}
        onChange={(event) => setDraft({ ...draft, url: event.currentTarget.value })}
      />
      <p className={styles.secondary}>{t('publicIpLookup.privacy')}</p>
      {save.isError && Object.keys(fields).length === 0 && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, save.error)}
        </Notice>
      )}
      {save.isSuccess && !dirty && (
        <Notice tone="info" role="status">
          {t('publicIpLookup.saved')}
        </Notice>
      )}
      <div className={styles.buttons}>
        <Button type="submit" variant="primary" disabled={!dirty} loading={save.isPending}>
          {t('publicIpLookup.save')}
        </Button>
      </div>
    </form>
  );
}
