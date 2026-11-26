import type { FieldErrors } from '../../../api/client';
import { schemaErrorKey } from '../schema/schemaValues';

export interface ProfileFormErrors {
  name?: string;
  dailyReconnectTime?: string;
  publicAddress?: string;
  /** By schema field key. */
  schema: Record<string, string>;
  /** Messages that belong to no visible field, shown above the form. */
  other: string[];
}

/** Sorts the server's `fields` onto the form: name, schedule, access, schema fields, the rest. */
export function splitProfileErrors(
  fields: FieldErrors,
  schemaKeys: readonly string[],
): ProfileFormErrors {
  const errors: ProfileFormErrors = { schema: {}, other: [] };
  for (const [key, message] of Object.entries(fields)) {
    const schemaKey = schemaErrorKey(key);
    if (key === 'name') {
      errors.name = message;
    } else if (key.startsWith('dailyReconnect')) {
      errors.dailyReconnectTime = message;
    } else if (key === 'publicAddress') {
      errors.publicAddress = message;
    } else if (schemaKeys.includes(schemaKey)) {
      errors.schema[schemaKey] = message;
    } else {
      errors.other.push(`${key}: ${message}`);
    }
  }
  return errors;
}
