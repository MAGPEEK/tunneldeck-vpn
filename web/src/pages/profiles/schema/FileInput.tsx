import { useTranslation } from 'react-i18next';
import styles from './SchemaForm.module.css';

/** Standard base64 (RFC 4648 §4) of bytes, encoded in chunks to stay within argument limits. */
function toBase64(bytes: Uint8Array): string {
  const chunk = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export interface FileInputProps {
  /** The label of the field the file fills. */
  fieldLabel: string;
  /** `base64` reads a binary file (e.g. PKCS#12) as base64, `text` a text file (e.g. PEM). */
  encoding: 'base64' | 'text';
  onValue: (value: string) => void;
}

/** A file picker that hands the chosen file's content to `onValue`; nothing is uploaded on its own. */
export function FileInput({ fieldLabel, encoding, onValue }: FileInputProps) {
  const { t } = useTranslation();
  const read = (file: File) =>
    encoding === 'base64'
      ? file.arrayBuffer().then((buffer) => toBase64(new Uint8Array(buffer)))
      : file.text();
  return (
    <label className={styles.fileLabel}>
      <span aria-hidden="true">{t('schemaForm.loadFile')}</span>
      <input
        type="file"
        aria-label={t('schemaForm.loadFileFor', { label: fieldLabel })}
        onChange={(event) => {
          const file = event.currentTarget.files?.[0];
          if (file) {
            void read(file).then(onValue);
          }
        }}
      />
    </label>
  );
}
