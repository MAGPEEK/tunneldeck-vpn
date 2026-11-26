import type { FormSchema, SchemaField } from '../../../api/profiles';
import {
  isVisible,
  schemaFields,
  type FormValues,
  type SecretState,
  type SecretStates,
} from '../schema/schemaValues';

function secretIsEmpty(state: SecretState | undefined): boolean {
  switch (state?.mode) {
    case 'stored':
      return false;
    case 'replace':
    case 'new':
      return state.value.trim() === '';
    default:
      return true;
  }
}

function valueIsEmpty(value: FormValues[string] | undefined): boolean {
  if (Array.isArray(value)) return value.every((line) => line.trim() === '');
  return typeof value !== 'boolean' && (value ?? '').trim() === '';
}

/**
 * The fields an import reported as missing that are shown and still empty,
 * in form order: they lose their highlight as soon as the user fills them.
 */
export function stillMissing(
  schema: FormSchema,
  missing: readonly string[],
  values: FormValues,
  secrets: SecretStates,
): SchemaField[] {
  return schemaFields(schema).filter(
    (field) =>
      missing.includes(field.key) &&
      isVisible(field, values, secrets) &&
      (field.type === 'secret'
        ? secretIsEmpty(secrets[field.key])
        : valueIsEmpty(values[field.key])),
  );
}
