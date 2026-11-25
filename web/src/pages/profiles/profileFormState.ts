/** Router state for the profile form. Secrets never go into history state. */
export interface ProfileFormState {
  /** The import draft waits in the query cache under queryKeys.importDraft. */
  fromImport?: boolean;
  duplicateOf?: string;
  /** Set after a create, so the edit view confirms the save. */
  saved?: boolean;
}

export function readProfileFormState(state: unknown): ProfileFormState {
  if (typeof state !== 'object' || state === null) {
    return {};
  }
  const record = state as Record<string, unknown>;
  return {
    fromImport: record.fromImport === true,
    duplicateOf: typeof record.duplicateOf === 'string' ? record.duplicateOf : undefined,
    saved: record.saved === true,
  };
}
