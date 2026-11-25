import { useTranslation } from 'react-i18next';
import type { ConnectionStatus } from '../../api/connection';
import { formatBitRate, formatBytes } from '../../format/format';
import styles from './MetricRow.module.css';

export function MetricRow({ status }: { status: ConnectionStatus }) {
  const { t, i18n } = useTranslation();
  const locale = i18n.resolvedLanguage ?? 'en';
  const live = status.state === 'connected' || status.state === 'reconnecting';
  const show = (value: string) => (live ? value : '–');
  const metrics = [
    { label: t('metrics.received'), value: show(formatBytes(status.bytesIn, locale)) },
    { label: t('metrics.sent'), value: show(formatBytes(status.bytesOut, locale)) },
    { label: t('metrics.download'), value: show(formatBitRate(status.rateIn, locale)) },
    { label: t('metrics.upload'), value: show(formatBitRate(status.rateOut, locale)) },
  ];
  return (
    <dl className={styles.row} aria-label={t('metrics.label')}>
      {metrics.map((metric) => (
        <div key={metric.label} className={styles.tile}>
          <dt className={styles.label}>{metric.label}</dt>
          <dd className={styles.value}>{metric.value}</dd>
        </div>
      ))}
    </dl>
  );
}
