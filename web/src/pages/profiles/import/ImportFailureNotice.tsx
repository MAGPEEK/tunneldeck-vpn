import { useTranslation } from 'react-i18next';
import { Notice } from '../../../components/Notice';
import type { ImportFailure } from './useProfileImport';

/** Why a profile file could not be loaded, titled with the file name. */
export function ImportFailureNotice({ failure }: { failure: ImportFailure }) {
  const { t } = useTranslation();
  return (
    <Notice
      tone="danger"
      role="alert"
      title={failure.fileName ? t('profiles.loadFailed', { file: failure.fileName }) : undefined}
    >
      {failure.message}
    </Notice>
  );
}
