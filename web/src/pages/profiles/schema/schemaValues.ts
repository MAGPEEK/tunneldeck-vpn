import type { FormSchema, SchemaField, SettingValue, Settings } from '../../../api/profiles';

/** Form values of the non-secret fields. Numbers are kept as typed text until submit. */
export type FormValues = Record<string, string | boolean | string[]>;

/**
 * A secret field's editing state: `stored` keeps the saved value, `replace`
 * and `new` send `value`, `remove` clears the saved value.
 */
export type SecretState =
  | { mode: 'stored' }
  | { mode: 'replace'; value: string }
  | { mode: 'remove' }
  | { mode: 'new'; value: string };

export type SecretStates = Record<string, SecretState>;

export interface SchemaRequestPart {
  settings: Settings;
  secrets: Record<string, string>;
  clearSecrets: string[];
}

export function schemaFields(schema: FormSchema): SchemaField[] {
  return schema.sections.flatMap((section) => section.fields);
}

function toFormValue(
  field: SchemaField,
  value: SettingValue | undefined,
): string | boolean | string[] {
  switch (field.type) {
    case 'bool':
      return typeof value === 'boolean' ? value : false;
    case 'stringList':
      return Array.isArray(value) ? value.map(String) : [];
    default:
      return value === undefined || Array.isArray(value) || typeof value === 'boolean'
        ? ''
        : String(value);
  }
}

/** Form values from saved settings, falling back to each field's default. */
export function initialValues(schema: FormSchema, settings: Settings = {}): FormValues {
  const values: FormValues = {};
  for (const field of schemaFields(schema)) {
    if (field.type !== 'secret') {
      values[field.key] = toFormValue(field, settings[field.key] ?? field.default);
    }
  }
  return values;
}

/**
 * Secret states: `stored` where the profile has a value, `new` (pre-filled
 * from an import draft when given) everywhere else.
 */
export function initialSecrets(
  schema: FormSchema,
  stored: Record<string, { hasValue: boolean }> = {},
  draft: Record<string, string> = {},
): SecretStates {
  const states: SecretStates = {};
  for (const field of schemaFields(schema)) {
    if (field.type === 'secret') {
      states[field.key] = stored[field.key]?.hasValue
        ? { mode: 'stored' }
        : { mode: 'new', value: draft[field.key] ?? '' };
    }
  }
  return states;
}

/** A secret has a value while it is stored, being replaced, or typed in. */
function secretHasValue(state: SecretState | undefined): boolean {
  switch (state?.mode) {
    case 'stored':
    case 'replace':
      return true;
    case 'new':
      return state.value.trim() !== '';
    default:
      return false;
  }
}

/**
 * Evaluates `visibleWhen`: either a setting holds one of the listed values,
 * or a secret field has a value.
 */
export function isVisible(field: SchemaField, values: FormValues, secrets: SecretStates): boolean {
  const condition = field.visibleWhen;
  if (!condition) {
    return true;
  }
  if ('secret' in condition) {
    return secretHasValue(secrets[condition.secret]);
  }
  const current = values[condition.key];
  return typeof current === 'string' && condition.equals.includes(current);
}

function toSetting(
  field: SchemaField,
  value: string | boolean | string[],
): SettingValue | undefined {
  switch (field.type) {
    case 'bool':
      return value === true;
    case 'stringList': {
      const lines = (Array.isArray(value) ? value : []).map((line) => line.trim()).filter(Boolean);
      return lines.length > 0 ? lines : undefined;
    }
    case 'number': {
      const text = typeof value === 'string' ? value.trim() : '';
      return text === '' ? undefined : Number(text);
    }
    default: {
      const text = typeof value === 'string' ? value : '';
      return text.trim() === '' ? undefined : text;
    }
  }
}

/**
 * The settings, secrets and clearSecrets of the API request. Hidden fields
 * and empty values are left out, so the server applies its defaults; a
 * secret is only sent when the user typed one.
 */
export function toRequestPart(
  schema: FormSchema,
  values: FormValues,
  secrets: SecretStates,
): SchemaRequestPart {
  const part: SchemaRequestPart = { settings: {}, secrets: {}, clearSecrets: [] };
  for (const field of schemaFields(schema)) {
    if (field.type === 'secret') {
      const state = secrets[field.key];
      if (state?.mode === 'remove') {
        part.clearSecrets.push(field.key);
      } else if (
        (state?.mode === 'replace' || state?.mode === 'new') &&
        state.value !== '' &&
        isVisible(field, values, secrets)
      ) {
        part.secrets[field.key] = state.value;
      }
      continue;
    }
    if (!isVisible(field, values, secrets)) {
      continue;
    }
    const setting = toSetting(field, values[field.key] ?? '');
    if (setting !== undefined) {
      part.settings[field.key] = setting;
    }
  }
  return part;
}

/**
 * Maps a server field-error key to a schema field key: `remoteHost`,
 * `settings.remoteHost` and `secrets.password` all name their field.
 */
export function schemaErrorKey(serverKey: string): string {
  return serverKey.replace(/^(settings|secrets)\./, '');
}
