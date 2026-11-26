import type { TFunction } from 'i18next';
import { translateDynamic } from '../i18n/dynamic';
import type { ApiError, FieldErrors } from './client';

/**
 * The field messages of a validation error in the UI language: each field
 * with a code the UI knows is translated (`fieldError.<code>` with the
 * code's params); any other field keeps the server's message.
 */
export function localizedFieldErrors(t: TFunction, error: ApiError): FieldErrors {
  return Object.fromEntries(
    Object.entries(error.fields).map(([field, message]) => {
      const issue = error.fieldCodes[field];
      const text = issue
        ? translateDynamic(t, `fieldError.${issue.code}`, message, issue.params)
        : message;
      return [field, text];
    }),
  );
}
