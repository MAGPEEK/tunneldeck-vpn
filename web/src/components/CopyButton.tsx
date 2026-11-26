import { Copy } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from './Button';

const COPIED_MS = 2000;

/** Copies `text` to the clipboard and says "Copied" for a moment. */
export function CopyButton({ text }: { text: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), COPIED_MS);
    } catch {
      setCopied(false);
    }
  };
  return (
    <Button icon={<Copy size={14} aria-hidden="true" />} onClick={() => void copy()}>
      {copied ? t('log.copied') : t('log.copy')}
    </Button>
  );
}
