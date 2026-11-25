import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import { queryKeys } from '../../api/queryKeys';
import {
  putRemoteAccess,
  type CertificateSource,
  type RemoteAccess,
  type RemoteAccessSettings,
} from '../../api/remoteAccess';
import { Button } from '../../components/Button';
import { Field } from '../../components/Field';
import { Notice } from '../../components/Notice';
import { genericErrorMessage } from '../auth/formError';
import { CheckboxField } from '../profiles/schema/CheckboxField';
import { CertificateDetails } from './CertificateDetails';
import { CertificateUploadForm } from './CertificateUploadForm';
import styles from './SystemPage.module.css';

const SOURCES: CertificateSource[] = ['selfSigned', 'uploaded'];

interface Draft {
  enabled: boolean;
  port: string;
  certificateSource: CertificateSource;
}

function toDraft(saved: RemoteAccess): Draft {
  return {
    enabled: saved.enabled,
    port: String(saved.port),
    certificateSource: saved.certificateSource,
  };
}

function toSettings(draft: Draft): RemoteAccessSettings {
  const port = Number(draft.port.trim());
  return {
    enabled: draft.enabled,
    port: Number.isInteger(port) ? port : 0,
    certificateSource: draft.certificateSource,
  };
}

export function RemoteAccessForm({ saved }: { saved: RemoteAccess }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [draft, setDraft] = useState(() => toDraft(saved));
  const save = useMutation({
    mutationFn: putRemoteAccess,
    onSuccess: (result) => {
      client.setQueryData(queryKeys.remoteAccess, result);
      setDraft(toDraft(result));
    },
  });
  const dirty = JSON.stringify(toSettings(draft)) !== JSON.stringify(toSettings(toDraft(saved)));
  const fields = isApiError(save.error) ? save.error.fields : {};

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    save.mutate(toSettings(draft));
  };

  return (
    <div className={styles.form}>
      <Notice tone="danger" title={t('remoteAccess.warningTitle')}>
        <p>{t('remoteAccess.warning')}</p>
      </Notice>
      <StatusLine saved={saved} />
      <form className={styles.form} onSubmit={submit}>
        <CheckboxField
          label={t('remoteAccess.enable')}
          checked={draft.enabled}
          error={fields.enabled}
          onChange={(enabled) => setDraft({ ...draft, enabled })}
        />
        <Field
          label={t('remoteAccess.port')}
          className={styles.portField}
          type="number"
          min={1}
          max={65535}
          inputMode="numeric"
          value={draft.port}
          error={fields.port}
          onChange={(event) => setDraft({ ...draft, port: event.currentTarget.value })}
        />
        <fieldset className={styles.radios}>
          <legend>{t('remoteAccess.source')}</legend>
          {SOURCES.map((source) => (
            <label key={source} className={styles.radio}>
              <input
                type="radio"
                name="certificateSource"
                value={source}
                checked={draft.certificateSource === source}
                onChange={() => setDraft({ ...draft, certificateSource: source })}
              />
              {t(`remoteAccess.sources.${source}`)}
            </label>
          ))}
        </fieldset>
        {fields.certificateSource && <p className={styles.danger}>{fields.certificateSource}</p>}
        {save.isError && Object.keys(fields).length === 0 && (
          <Notice tone="danger" role="alert">
            {genericErrorMessage(t, save.error)}
          </Notice>
        )}
        {save.isSuccess && !dirty && (
          <Notice tone="info" role="status">
            {t('remoteAccess.saved')}
          </Notice>
        )}
        <div className={styles.buttons}>
          <Button type="submit" variant="primary" disabled={!dirty} loading={save.isPending}>
            {t('remoteAccess.save')}
          </Button>
        </div>
      </form>
      {saved.certificate && <CertificateDetails certificate={saved.certificate} />}
      {draft.certificateSource === 'uploaded' && <CertificateUploadForm />}
    </div>
  );
}

function StatusLine({ saved }: { saved: RemoteAccess }) {
  const { t } = useTranslation();
  if (saved.lastError) {
    return (
      <p className={styles.danger} role="status">
        {t('remoteAccess.lastError', { error: saved.lastError })}
      </p>
    );
  }
  let text = t('remoteAccess.off');
  if (saved.enabled) {
    text = saved.listening
      ? t('remoteAccess.listening', { port: saved.port })
      : t('remoteAccess.notListening');
  }
  return (
    <p className={styles.secondary} role="status">
      {text}
    </p>
  );
}
