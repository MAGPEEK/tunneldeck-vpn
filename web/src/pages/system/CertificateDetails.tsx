import { useTranslation } from 'react-i18next';
import type { Certificate } from '../../api/remoteAccess';
import { CopyButton } from '../../components/CopyButton';
import styles from './SystemPage.module.css';

export function CertificateDetails({ certificate }: { certificate: Certificate }) {
  const { t, i18n } = useTranslation();
  const validUntil = new Date(certificate.notAfter);
  const shownUntil = Number.isNaN(validUntil.getTime())
    ? certificate.notAfter
    : new Intl.DateTimeFormat(i18n.resolvedLanguage ?? 'en', { dateStyle: 'medium' }).format(
        validUntil,
      );

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
        <CopyButton text={certificate.fingerprintSha256} />
      </dd>
    </dl>
  );
}
