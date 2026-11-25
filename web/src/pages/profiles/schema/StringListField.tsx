import { Plus, X } from 'lucide-react';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../../../components/Button';
import fieldStyles from '../../../components/Field.module.css';
import styles from './SchemaForm.module.css';

export interface StringListFieldProps {
  label: string;
  lines: string[];
  placeholder?: string;
  error?: string;
  onChange: (lines: string[]) => void;
}

/** One input per line, a remove button per row and an add button on the last row. */
export function StringListField({
  label,
  lines,
  placeholder,
  error,
  onChange,
}: StringListFieldProps) {
  const { t } = useTranslation();
  const errorId = useId();
  const rows = lines.length === 0 ? [''] : lines;
  const update = (index: number, value: string) =>
    onChange(rows.map((line, i) => (i === index ? value : line)));
  const remove = (index: number) => onChange(rows.filter((_, i) => i !== index));
  const add = () => onChange([...rows, '']);

  return (
    <fieldset className={styles.group} aria-describedby={error ? errorId : undefined}>
      <legend className={styles.legend}>{label}</legend>
      {rows.map((line, index) => (
        <div key={index} className={styles.listRow}>
          <input
            className={`${fieldStyles.control} ${styles.mono}`}
            aria-label={t('schemaForm.line', { label, number: index + 1 })}
            aria-invalid={error ? true : undefined}
            value={line}
            placeholder={index === 0 ? placeholder : undefined}
            spellCheck={false}
            autoComplete="off"
            onChange={(event) => update(index, event.currentTarget.value)}
          />
          <Button
            variant="ghost"
            className={styles.iconButton}
            aria-label={t('schemaForm.removeLine', { number: index + 1 })}
            disabled={rows.length === 1 && line === ''}
            onClick={() => remove(index)}
          >
            <X size={16} aria-hidden="true" />
          </Button>
          {index === rows.length - 1 && (
            <Button
              className={styles.iconButton}
              aria-label={t('schemaForm.addLine')}
              onClick={add}
            >
              <Plus size={16} aria-hidden="true" />
            </Button>
          )}
        </div>
      ))}
      {error && (
        <p id={errorId} className={styles.error}>
          {error}
        </p>
      )}
    </fieldset>
  );
}
