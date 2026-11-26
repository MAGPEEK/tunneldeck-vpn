import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { isApiError } from '../../../api/client';
import { localizedFieldErrors } from '../../../api/fieldErrors';
import { importProfile, type ImportDraft } from '../../../api/profiles';
import { queryKeys } from '../../../api/queryKeys';
import { genericErrorMessage } from '../../auth/formError';
import type { ProfileFormState } from '../profileFormState';
import { isProfileFileName, MAX_PROFILE_FILE_BYTES, readProfileFile } from './profileFile';

const IMPORT_PROTOCOL = 'openvpn';

/** The import draft in the query cache, with the name of the loaded file. */
export interface CachedImportDraft extends ImportDraft {
  fileName?: string;
}

/** Why loading failed; fileName is set when a file was loaded. */
export interface ImportFailure {
  fileName?: string;
  message: string;
}

interface ImportInput {
  text: string;
  fileName?: string;
}

/** The translated reason a validation error gives for the file or text. */
function importErrorMessage(t: TFunction, error: unknown): string {
  if (isApiError(error) && error.code === 'validation_failed') {
    const fields = localizedFieldErrors(t, error);
    return fields.file ?? fields.text ?? t('profiles.importInvalid');
  }
  return genericErrorMessage(t, error);
}

/**
 * Sends a profile file or pasted text to the importer and opens the
 * pre-filled new-profile form. Files that are not .ovpn/.conf, too large
 * or unreadable fail before anything is sent.
 */
export function useProfileImport() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const [localFailure, setLocalFailure] = useState<ImportFailure>();
  const parse = useMutation({
    mutationFn: ({ text }: ImportInput) => importProfile(IMPORT_PROTOCOL, text),
    onSuccess: (draft, { fileName }) => {
      const cached: CachedImportDraft = { ...draft, fileName };
      client.setQueryData(queryKeys.importDraft, cached);
      const state: ProfileFormState = { fromImport: true };
      void navigate('/profiles/new', { state });
    },
  });

  const fail = (fileName: string, message: string) => {
    parse.reset();
    setLocalFailure({ fileName, message });
  };

  const loadFile = async (file: File) => {
    if (!isProfileFileName(file.name)) {
      fail(file.name, t('profiles.importWrongType'));
      return;
    }
    if (file.size > MAX_PROFILE_FILE_BYTES) {
      fail(file.name, t('fieldError.file_too_large', { max: '1 MiB' }));
      return;
    }
    let text: string;
    try {
      text = await readProfileFile(file);
    } catch {
      fail(file.name, t('profiles.importUnreadable'));
      return;
    }
    setLocalFailure(undefined);
    parse.mutate({ text, fileName: file.name });
  };

  const loadText = (text: string) => {
    setLocalFailure(undefined);
    parse.mutate({ text });
  };

  const failure: ImportFailure | undefined =
    localFailure ??
    (parse.isError
      ? { fileName: parse.variables.fileName, message: importErrorMessage(t, parse.error) }
      : undefined);

  return { loadFile, loadText, pending: parse.isPending, failure };
}
