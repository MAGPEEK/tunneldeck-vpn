import { useTranslation } from 'react-i18next';
import styles from './SchemaForm.module.css';

/** Largest file a field takes: as base64 it must still fit into the 1 MiB request body. */
const MAX_FIELD_FILE_BYTES = 512 * 1024;
const MAX_FIELD_FILE_SIZE = '512 KiB';

/** Standard base64 (RFC 4648 §4) of bytes, encoded in chunks to stay within argument limits. */
function toBase64(bytes: Uint8Array): string {
  const chunk = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function readFile(file: File, encoding: FileInputProps['encoding']): Promise<string> {
  return encoding === 'base64'
    ? file.arrayBuffer().then((buffer) => toBase64(new Uint8Array(buffer)))
    : file.text();
}

export interface FileInputProps {
  /** The label of the field the file fills. */
  fieldLabel: string;
  /** `base64` reads a binary file (e.g. PKCS#12) as base64, `text` a text file (e.g. PEM). */
  encoding: 'base64' | 'text';
  onValue: (value: string) => void;
  /** The translated reason the chosen file was not taken; undefined once a file was read. */
  onError: (message: string | undefined) => void;
}

/** A file picker that hands the chosen file's content to `onValue`; nothing is uploaded on its own. */
export function FileInput({ fieldLabel, encoding, onValue, onError }: FileInputProps) {
  const { t } = useTranslation();
  const load = async (input: HTMLInputElement) => {
    const file = input.files?.[0];
    // Cleared so that choosing the same file again reads it again.
    input.value = '';
    if (!file) {
      return;
    }
    if (file.size > MAX_FIELD_FILE_BYTES) {
      onError(t('fieldError.file_too_large', { max: MAX_FIELD_FILE_SIZE }));
      return;
    }
    let value: string;
    try {
      value = await readFile(file, encoding);
    } catch {
      onError(t('schemaForm.fileUnreadable'));
      return;
    }
    onError(undefined);
    onValue(value);
  };
  return (
    <label className={styles.fileLabel}>
      <span aria-hidden="true">{t('schemaForm.loadFile')}</span>
      <input
        type="file"
        aria-label={t('schemaForm.loadFileFor', { label: fieldLabel })}
        onChange={(event) => void load(event.currentTarget)}
      />
    </label>
  );
}
