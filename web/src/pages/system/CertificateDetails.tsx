import { Copy } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Certificate } from '../../api/remoteAccess';
import { Button } from '../../components/Button';
import styles from './SystemPage.module.css';

export function CertificateDetails({ certificate }: { certificate: Certificate }) {
  const { t, i18n } = useTranslation();
  const [copied, setCopied] = useState(false);
  const validUntil = new Date(certificate.notAfter);
  const shownUntil = Number.isNaN(validUntil.getTime())
    ? certificate.notAfter
    : new Intl.DateTimeFormat(i18n.resolvedLanguage ?? 'en', { dateStyle: 'medium' }).format(
        validUntil,
      );

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(certificate.fingerprintSha256);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <dl className={styles.values} aria-label={t('remoteAccess.certificate')}>
      <dt>{t('remoteAccess.subject')}</dt>
      <dd>
        {certificate.subject}
        {certificate.selfSigned && (
          <span className={styles.secondary}> ({t('remoteAccess.selfSignedNote')})</span>
        )}
      </dd>
      <dt>{t('remoteAccess.validUntil')}</dt>
      <dd>{shownUntil}</dd>
      <dt>{t('remoteAccess.fingerprint')}</dt>
      <dd className={styles.fingerprint}>
        <code>{certificate.fingerprintSha256}</code>
        <Button icon={<Copy size={14} aria-hidden="true" />} onClick={() => void copy()}>
          {copied ? t('log.copied') : t('log.copy')}
        </Button>
      </dd>
    </dl>
  );
}
