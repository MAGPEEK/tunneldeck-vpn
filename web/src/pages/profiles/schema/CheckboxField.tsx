import { useId, type ReactNode } from 'react';
import styles from './SchemaForm.module.css';

export interface CheckboxFieldProps {
  label: ReactNode;
  checked: boolean;
  error?: string;
  hint?: ReactNode;
  onChange: (checked: boolean) => void;
}

export function CheckboxField({ label, checked, error, hint, onChange }: CheckboxFieldProps) {
  const id = useId();
  const describedBy = [hint ? `${id}-hint` : '', error ? `${id}-error` : '']
    .filter(Boolean)
    .join(' ');
  return (
    <div className={styles.checkbox}>
      <label className={styles.checkboxLabel}>
        <input
          type="checkbox"
          checked={checked}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy || undefined}
          onChange={(event) => onChange(event.currentTarget.checked)}
        />
        {label}
      </label>
      {hint && (
        <p id={`${id}-hint`} className={styles.storedText}>
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className={styles.error}>
          {error}
        </p>
      )}
    </div>
  );
}
