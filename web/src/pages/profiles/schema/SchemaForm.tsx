import type { FormSchema, SchemaField } from '../../../api/profiles';
import { Card } from '../../../components/Card';
import { useDriverText } from '../../../i18n/dynamic';
import { CheckboxField } from './CheckboxField';
import { SecretField } from './SecretField';
import { StringListField } from './StringListField';
import { SelectField, TextAreaField, TextField } from './ValueFields';
import { isVisible, type FormValues, type SecretState, type SecretStates } from './schemaValues';
import styles from './SchemaForm.module.css';

export interface SchemaFormProps {
  schema: FormSchema;
  values: FormValues;
  secrets: SecretStates;
  errors: Record<string, string>;
  onValuesChange: (values: FormValues) => void;
  onSecretsChange: (secrets: SecretStates) => void;
}

/** Renders a driver's FormSchema: one card per section, fields shown per `visibleWhen`. */
export function SchemaForm(props: SchemaFormProps) {
  const { schema, values } = props;
  const text = useDriverText();
  return (
    <>
      {schema.sections.map((section) => {
        const fields = section.fields.filter((field) => isVisible(field, values));
        if (fields.length === 0) {
          return null;
        }
        return (
          <Card key={section.key} title={text(section.labelKey)}>
            <div className={styles.fields}>
              {fields.map((field) => (
                <SchemaInput key={field.key} field={field} {...props} />
              ))}
            </div>
          </Card>
        );
      })}
    </>
  );
}

interface SchemaInputProps extends SchemaFormProps {
  field: SchemaField;
}

function SchemaInput({
  field,
  values,
  secrets,
  errors,
  onValuesChange,
  onSecretsChange,
}: SchemaInputProps) {
  const text = useDriverText();
  const label = text(field.labelKey);
  const error = errors[field.key];
  const value = values[field.key];
  const setValue = (next: string | boolean | string[]) =>
    onValuesChange({ ...values, [field.key]: next });
  const setSecret = (next: SecretState) => onSecretsChange({ ...secrets, [field.key]: next });

  switch (field.type) {
    case 'bool':
      return (
        <CheckboxField label={label} checked={value === true} error={error} onChange={setValue} />
      );
    case 'stringList':
      return (
        <StringListField
          label={label}
          lines={Array.isArray(value) ? value : []}
          placeholder={field.placeholder}
          error={error}
          onChange={setValue}
        />
      );
    case 'secret':
      return (
        <SecretField
          field={field}
          label={label}
          state={secrets[field.key] ?? { mode: 'new', value: '' }}
          error={error}
          onChange={setSecret}
        />
      );
    case 'select':
      return (
        <SelectField
          label={label}
          value={typeof value === 'string' ? value : ''}
          options={(field.options ?? []).map((option) => ({
            value: option.value,
            label: text(option.labelKey),
          }))}
          error={error}
          onChange={setValue}
        />
      );
    case 'textarea':
      return (
        <TextAreaField
          label={label}
          value={typeof value === 'string' ? value : ''}
          required={field.required}
          placeholder={field.placeholder}
          error={error}
          onChange={setValue}
        />
      );
    case 'number':
    case 'text':
      return (
        <TextField
          label={label}
          type={field.type}
          value={typeof value === 'string' ? value : ''}
          required={field.required}
          placeholder={field.placeholder}
          error={error}
          onChange={setValue}
        />
      );
  }
}
