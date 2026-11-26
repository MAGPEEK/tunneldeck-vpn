import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type ChangeEvent, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { isApiError } from '../../api/client';
import { localizedFieldErrors } from '../../api/fieldErrors';
import { importProfile } from '../../api/profiles';
import { queryKeys } from '../../api/queryKeys';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Field } from '../../components/Field';
import { Notice } from '../../components/Notice';
import { genericErrorMessage } from '../auth/formError';
import type { ProfileFormState } from './profileFormState';
import styles from './ImportPanel.module.css';

const IMPORT_PROTOCOL = 'openvpn';

/** Reads an .ovpn file or pasted text and opens the new-profile form with the draft. */
export function ImportPanel({ onCancel }: { onCancel: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const [text, setText] = useState('');
  const parse = useMutation({
    mutationFn: (configText: string) => importProfile(IMPORT_PROTOCOL, configText),
    onSuccess: (draft) => {
      client.setQueryData(queryKeys.importDraft, draft);
      const state: ProfileFormState = { fromImport: true };
      void navigate('/profiles/new', { state });
    },
  });

  const readFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    if (file) {
      setText(await file.text());
    }
  };

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    parse.mutate(text);
  };

  const importFields =
    isApiError(parse.error) && parse.error.code === 'validation_failed'
      ? localizedFieldErrors(t, parse.error)
      : undefined;
  const fieldError = importFields
    ? (importFields.file ?? importFields.text ?? t('profiles.importInvalid'))
    : undefined;

  return (
    <Card title={t('profiles.importTitle')}>
      <form className={styles.form} onSubmit={submit}>
        <Field
          label={t('profiles.importFile')}
          type="file"
          accept=".ovpn,.conf,text/plain"
          onChange={(event) => void readFile(event)}
        />
        <Field label={t('profiles.importPaste')} error={fieldError}>
          {(control) => (
            <textarea
              {...control}
              className={`${control.className ?? ''} ${styles.mono}`}
              rows={8}
              spellCheck={false}
              value={text}
              onChange={(event) => setText(event.currentTarget.value)}
            />
          )}
        </Field>
        {parse.isError && fieldError === undefined && (
          <Notice tone="danger" role="alert">
            {genericErrorMessage(t, parse.error)}
          </Notice>
        )}
        <div className={styles.buttons}>
          <Button type="submit" loading={parse.isPending} disabled={text.trim() === ''}>
            {t('profiles.importSubmit')}
          </Button>
          <Button variant="ghost" onClick={onCancel}>
            {t('profiles.cancel')}
          </Button>
        </div>
      </form>
    </Card>
  );
}
