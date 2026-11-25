import { useId, type InputHTMLAttributes, type ReactNode } from 'react';
import styles from './Field.module.css';

/** Props a custom control (select, textarea, …) must spread to stay bound to the field. */
export interface FieldControlProps {
  id: string;
  className: string | undefined;
  'aria-describedby': string | undefined;
  'aria-invalid': true | undefined;
}

export interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'children'> {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  children?: (control: FieldControlProps) => ReactNode;
}

export function Field({ label, hint, error, children, className, ...inputProps }: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const hasError = error !== undefined && error !== null && error !== '';
  const describedBy = [hint ? hintId : '', hasError ? errorId : ''].filter(Boolean).join(' ');
  const control: FieldControlProps = {
    id,
    className: styles.control,
    'aria-describedby': describedBy || undefined,
    'aria-invalid': hasError || undefined,
  };
  return (
    <div className={[styles.field, className ?? ''].filter(Boolean).join(' ')}>
      <label htmlFor={id} className={styles.label}>
        {label}
      </label>
      {children ? children(control) : <input {...inputProps} {...control} />}
      {hint && (
        <p id={hintId} className={styles.hint}>
          {hint}
        </p>
      )}
      {hasError && (
        <p id={errorId} className={styles.error}>
          {error}
        </p>
      )}
    </div>
  );
}
