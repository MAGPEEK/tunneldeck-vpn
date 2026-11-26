import { useTranslation } from 'react-i18next';
import type { SystemInfo } from '../../api/system';
import { Card } from '../../components/Card';
import { formatZonedTime, parseTime } from '../../format/format';
import { formatUptime } from '../../format/uptime';
import { useNow } from '../../hooks/useNow';
import styles from './SystemPage.module.css';

const MINUTE_MS = 60_000;

/** How long since `start`, with the absolute start time as its title. */
function RunningFor({ start, now, timeZone }: { start: Date; now: number; timeZone: string }) {
  const { t, i18n } = useTranslation();
  const iso = start.toISOString();
  const time = formatZonedTime(iso, i18n.resolvedLanguage ?? 'en', timeZone);
  return (
    <time dateTime={iso} title={t('system.startedAt', { time })}>
      {formatUptime(t, (now - start.getTime()) / 1000)}
    </time>
  );
}

export function VersionCard({ system }: { system: SystemInfo }) {
  const { t, i18n } = useTranslation();
  const locale = i18n.resolvedLanguage ?? 'en';
  const now = useNow(MINUTE_MS);
  const processStart = parseTime(system.startedAt);
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
        {processStart && (
          <>
            <dt>{t('system.containerUptime')}</dt>
            <dd>
              <RunningFor start={processStart} now={now} timeZone={system.timeZone} />
            </dd>
          </>
        )}
      </dl>
    </Card>
  );
}
