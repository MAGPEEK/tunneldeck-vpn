import { Field } from '../../../components/Field';
import styles from './SchemaForm.module.css';

interface ValueFieldProps {
  label: string;
  value: string;
  error?: string;
  required?: boolean;
  placeholder?: string;
  onChange: (value: string) => void;
}

export function TextField({
  type,
  onChange,
  ...props
}: ValueFieldProps & { type: 'text' | 'number' }) {
  return (
    <Field
      {...props}
      type={type}
      inputMode={type === 'number' ? 'numeric' : undefined}
      autoComplete="off"
      spellCheck={false}
      onChange={(event) => onChange(event.currentTarget.value)}
    />
  );
}

export function TextAreaField({
  label,
  value,
  error,
  required,
  placeholder,
  onChange,
}: ValueFieldProps) {
  return (
    <Field label={label} error={error}>
      {(control) => (
        <textarea
          {...control}
          className={`${control.className ?? ''} ${styles.mono}`}
          value={value}
          required={required}
          placeholder={placeholder}
          spellCheck={false}
          rows={5}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
      )}
    </Field>
  );
}

export interface SelectFieldProps extends Omit<ValueFieldProps, 'placeholder' | 'required'> {
  options: { value: string; label: string }[];
}

export function SelectField({ label, value, options, error, onChange }: SelectFieldProps) {
  return (
    <Field label={label} error={error}>
      {(control) => (
        <select
          {...control}
          value={value}
          onChange={(event) => onChange(event.currentTarget.value)}
        >
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      )}
    </Field>
  );
}
