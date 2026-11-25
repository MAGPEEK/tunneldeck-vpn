import { useTranslation } from 'react-i18next';
import type { SystemInfo } from '../../api/system';
import { Card } from '../../components/Card';
import { formatZonedTime } from '../../format/format';
import styles from './SystemPage.module.css';

export function VersionCard({ system }: { system: SystemInfo }) {
  const { t, i18n } = useTranslation();
  const locale = i18n.resolvedLanguage ?? 'en';
  return (
    <Card title={t('system.versionTitle')}>
      <dl className={styles.values}>
        <dt>{t('system.version')}</dt>
        <dd className={styles.mono}>{system.version}</dd>
        <dt>{t('system.listenAddress')}</dt>
        <dd className={styles.mono}>{system.listenAddress}</dd>
        <dt>{t('system.serverTime')}</dt>
        <dd>
          {formatZonedTime(system.serverTime, locale, system.timeZone)}{' '}
          <span className={styles.secondary}>({system.timeZone})</span>
        </dd>
      </dl>
    </Card>
  );
}
