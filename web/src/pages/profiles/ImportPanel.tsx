import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Field } from '../../components/Field';
import type { ImportFailure } from './import/useProfileImport';
import styles from './ImportPanel.module.css';

export interface ImportPanelProps {
  pending: boolean;
  /** A failure of the pasted text; file failures are shown by the page. */
  failure: ImportFailure | undefined;
  onSubmit: (text: string) => void;
  onCancel: () => void;
}

/** Pasted configuration text, the secondary way to import a profile. */
export function ImportPanel({ pending, failure, onSubmit, onCancel }: ImportPanelProps) {
  const { t } = useTranslation();
  const [text, setText] = useState('');

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit(text);
  };

  return (
    <Card title={t('profiles.importTitle')}>
      <form className={styles.form} onSubmit={submit}>
        <Field label={t('profiles.importPaste')} error={failure?.message}>
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
        <div className={styles.buttons}>
          <Button type="submit" loading={pending} disabled={text.trim() === ''}>
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
