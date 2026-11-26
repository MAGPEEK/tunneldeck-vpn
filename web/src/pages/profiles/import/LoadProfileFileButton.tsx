import { FileUp } from 'lucide-react';
import { useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../../../components/Button';
import { PROFILE_FILE_ACCEPT } from './profileFile';

export interface LoadProfileFileButtonProps {
  loading: boolean;
  onFile: (file: File) => void;
}

/** "Load .ovpn file": a primary button that opens the file picker. */
export function LoadProfileFileButton({ loading, onFile }: LoadProfileFileButtonProps) {
  const { t } = useTranslation();
  const input = useRef<HTMLInputElement>(null);
  return (
    <>
      <Button
        variant="primary"
        icon={<FileUp size={16} aria-hidden="true" />}
        loading={loading}
        onClick={() => input.current?.click()}
      >
        {t('profiles.loadFile')}
      </Button>
      <input
        ref={input}
        type="file"
        accept={PROFILE_FILE_ACCEPT}
        hidden
        data-testid="profile-file-input"
        onChange={(event) => {
          const file = event.currentTarget.files?.[0];
          event.currentTarget.value = '';
          if (file) {
            onFile(file);
          }
        }}
      />
    </>
  );
}
