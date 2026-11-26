import type { FormSchema, SchemaField, SchemaOption, SettingValue } from '../../../api/profiles';
import { schemaFields, type FormValues } from '../schema/schemaValues';

/** A template choice: the select field and the option that was chosen. */
export interface TemplateChoice {
  field: SchemaField;
  option: SchemaOption;
}

/** The outcome of choosing a template: the new form values and the fields left as the user set them. */
export interface PresetResult {
  values: FormValues;
  /** Keys of preset fields that kept the user's own value. */
  kept: string[];
}

/** Select fields whose options pre-fill other fields (templates). */
export function templateFields(schema: FormSchema): SchemaField[] {
  return schemaFields(schema).filter(
    (field) => field.type === 'select' && field.options?.some((option) => option.presets),
  );
}

/** The template whose select value differs between `before` and `after`; undefined when none changed. */
export function changedTemplate(
  schema: FormSchema,
  before: FormValues,
  after: FormValues,
): TemplateChoice | undefined {
  for (const field of templateFields(schema)) {
    const value = after[field.key];
    if (value === before[field.key]) continue;
    const option = field.options?.find((candidate) => candidate.value === value);
    if (option) return { field, option };
  }
  return undefined;
}

/**
 * Applies a chosen template's presets. A field takes the preset unless the
 * user changed it: its value still equals what the previously chosen
 * template set (or the field default), or it is empty. Fields the user
 * changed keep their value and are listed in `kept`.
 */
export function applyTemplate(
  schema: FormSchema,
  before: FormValues,
  choice: TemplateChoice,
): PresetResult {
  const fields = new Map(schemaFields(schema).map((field) => [field.key, field]));
  const previous = choice.field.options?.find(
    (option) => option.value === before[choice.field.key],
  );
  const values: FormValues = { ...before, [choice.field.key]: choice.option.value };
  const kept: string[] = [];
  for (const [key, preset] of Object.entries(choice.option.presets ?? {})) {
    const field = fields.get(key);
    if (!field) continue;
    const current = before[key];
    const baseline = asFormValue(previous?.presets?.[key] ?? field.default);
    const next = asFormValue(preset);
    if (isEmpty(current) || sameValue(current, baseline)) {
      values[key] = next;
    } else if (!sameValue(current, next)) {
      kept.push(key);
    }
  }
  return { values, kept };
}

/** Sets every preset of the template, also over the user's own values. */
export function forceTemplate(
  schema: FormSchema,
  before: FormValues,
  choice: TemplateChoice,
): FormValues {
  const known = new Set(schemaFields(schema).map((field) => field.key));
  const values: FormValues = { ...before, [choice.field.key]: choice.option.value };
  for (const [key, preset] of Object.entries(choice.option.presets ?? {})) {
    if (known.has(key)) values[key] = asFormValue(preset);
  }
  return values;
}

function asFormValue(value: SettingValue | undefined): string | boolean | string[] {
  if (value === undefined) return '';
  if (Array.isArray(value)) return value.map(String);
  return typeof value === 'number' ? String(value) : value;
}

function isEmpty(value: string | boolean | string[] | undefined): boolean {
  if (value === undefined) return true;
  if (Array.isArray(value)) return value.every((line) => line.trim() === '');
  return typeof value === 'string' && value.trim() === '';
}

function sameValue(
  a: string | boolean | string[] | undefined,
  b: string | boolean | string[],
): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    const lines = a.map((line) => line.trim()).filter(Boolean);
    return lines.length === b.length && lines.every((line, index) => line === b[index]);
  }
  return a === b;
}
