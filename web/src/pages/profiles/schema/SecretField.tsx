import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import type { SchemaField } from '../../../api/profiles';
import { Button } from '../../../components/Button';
import { Field } from '../../../components/Field';
import fieldStyles from '../../../components/Field.module.css';
import type { SecretState } from './schemaValues';
import styles from './SchemaForm.module.css';

export interface SecretFieldProps {
  field: SchemaField;
  label: string;
  state: SecretState;
  error?: string;
  onChange: (state: SecretState) => void;
}

/**
 * A secret is never shown. A saved one reads "Stored" with Replace (and
 * Remove when optional); replacing shows an empty input with Keep stored.
 */
export function SecretField({ field, label, state, error, onChange }: SecretFieldProps) {
  if (state.mode === 'stored' || state.mode === 'remove') {
    return (
      <StoredSecret
        field={field}
        label={label}
        removed={state.mode === 'remove'}
        error={error}
        onChange={onChange}
      />
    );
  }
  const replacing = state.mode === 'replace';
  return (
    <SecretInput
      field={field}
      label={label}
      value={state.value}
      error={error}
      onValue={(value) => onChange(replacing ? { mode: 'replace', value } : { mode: 'new', value })}
      onKeep={replacing ? () => onChange({ mode: 'stored' }) : undefined}
    />
  );
}

interface StoredSecretProps {
  field: SchemaField;
  label: string;
  removed: boolean;
  error?: string;
  onChange: (state: SecretState) => void;
}

function StoredSecret({ field, label, removed, error, onChange }: StoredSecretProps) {
  const { t } = useTranslation();
  const labelId = useId();
  return (
    <div className={fieldStyles.field} role="group" aria-labelledby={labelId}>
      <span id={labelId} className={fieldStyles.label}>
        {label}
      </span>
      <div className={styles.stored}>
        {removed ? (
          <>
            <span className={styles.storedText}>{t('schemaForm.secretRemoved')}</span>
            <Button onClick={() => onChange({ mode: 'stored' })}>{t('schemaForm.undo')}</Button>
          </>
        ) : (
          <>
            <span className={styles.storedText}>{t('schemaForm.secretStored')}</span>
            <Button onClick={() => onChange({ mode: 'replace', value: '' })}>
              {t('schemaForm.replace')}
            </Button>
            {!field.required && (
              <Button variant="ghost" onClick={() => onChange({ mode: 'remove' })}>
                {t('schemaForm.remove')}
              </Button>
            )}
          </>
        )}
      </div>
      {error && <p className={fieldStyles.error}>{error}</p>}
    </div>
  );
}

interface SecretInputProps {
  field: SchemaField;
  label: string;
  value: string;
  error?: string;
  onValue: (value: string) => void;
  onKeep?: () => void;
}

function SecretInput({ field, label, value, error, onValue, onKeep }: SecretInputProps) {
  const { t } = useTranslation();
  const keep = onKeep && (
    <Button variant="ghost" onClick={onKeep}>
      {t('schemaForm.keepStored')}
    </Button>
  );
  if (field.multiline) {
    return (
      <Field label={label} error={error} hint={keep}>
        {(control) => (
          <textarea
            {...control}
            className={`${control.className ?? ''} ${styles.mono}`}
            value={value}
            required={field.required && !onKeep}
            placeholder={field.placeholder}
            spellCheck={false}
            autoComplete="off"
            rows={5}
            onChange={(event) => onValue(event.currentTarget.value)}
          />
        )}
      </Field>
    );
  }
  return (
    <Field
      label={label}
      error={error}
      hint={keep}
      type="password"
      autoComplete="new-password"
      value={value}
      required={field.required && !onKeep}
      placeholder={field.placeholder}
      onChange={(event) => onValue(event.currentTarget.value)}
    />
  );
}
