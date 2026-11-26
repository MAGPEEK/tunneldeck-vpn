import { useTranslation } from 'react-i18next';
import type { FormSchema, SchemaField } from '../../../api/profiles';
import { Button } from '../../../components/Button';
import fieldStyles from '../../../components/Field.module.css';
import { Notice } from '../../../components/Notice';
import { useDriverText, useOptionalDriverText } from '../../../i18n/dynamic';
import { schemaFields } from '../schema/schemaValues';
import styles from './ProfileForm.module.css';

export interface TemplatePanelProps {
  schema: FormSchema;
  /** The template select field. */
  field: SchemaField;
  /** The chosen option's value. */
  value: string;
  /** Preset fields that kept the user's own value on the last template change. */
  kept: readonly string[];
  /** Overwrites the kept fields with the template's values. */
  onForce: () => void;
}

/**
 * Below a template select: the chosen template's hint (where to find the
 * values on the gateway), and after a template change the fields that kept
 * the user's values with "Use template values".
 */
export function TemplatePanel({ schema, field, value, kept, onForce }: TemplatePanelProps) {
  const { t } = useTranslation();
  const text = useDriverText();
  const optionalText = useOptionalDriverText();
  const option = field.options?.find((candidate) => candidate.value === value);
  const hint = option ? optionalText(`${option.labelKey}.hint`) : undefined;
  const labels = new Map(schemaFields(schema).map((f) => [f.key, text(f.labelKey)]));
  if (!hint && kept.length === 0) {
    return null;
  }
  return (
    <div className={styles.addon}>
      {hint && <p className={fieldStyles.hint}>{hint}</p>}
      {kept.length > 0 && (
        <Notice
          tone="info"
          role="status"
          actions={<Button onClick={onForce}>{t('profileForm.templateApply')}</Button>}
        >
          <p>
            {t('profileForm.templateKept', {
              fields: kept.map((key) => labels.get(key) ?? key).join(', '),
            })}
          </p>
        </Notice>
      )}
    </div>
  );
}
