import { TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { AuditEntry, AuditFilter } from '../../api/audit';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Notice } from '../../components/Notice';
import { StatePill, type StateTone } from '../../components/StatePill';
import { Table, type Column } from '../../components/Table';
import { formatZonedTime } from '../../format/format';
import { useAudit, useSystem } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import styles from './SystemPage.module.css';

const FILTERS: AuditFilter[] = ['', 'failures', 'security'];

/** A successful sign-in is green; otherwise the severity sets the colour. */
function entryTone(entry: AuditEntry): StateTone {
  if (entry.type === 'signedIn') {
    return 'success';
  }
  switch (entry.severity) {
    case 'warning':
      return 'danger';
    case 'notice':
      return 'warning';
    default:
      return 'neutral';
  }
}

/**
 * How a row stands out: `attack` (warning-level security events) is danger-tinted,
 * `failure` (notice-level, e.g. a wrong password) is milder amber. Successes and
 * plain info rows return `null` and stay normal. Each kind carries its own icon,
 * tone and label so it reads without relying on colour alone.
 */
interface RowMark {
  kind: 'attack' | 'failure';
  tone: StateTone;
  labelKey: 'system.audit.attackTag' | 'system.audit.failureTag';
}

function rowMark(entry: AuditEntry): RowMark | null {
  switch (entry.severity) {
    case 'warning':
      return { kind: 'attack', tone: 'danger', labelKey: 'system.audit.attackTag' };
    case 'notice':
      return { kind: 'failure', tone: 'warning', labelKey: 'system.audit.failureTag' };
    default:
      return null;
  }
}

/** SPEC §8.2: sign-ins, sign-outs and blocked attacks, newest first. */
export function AuditCard() {
  const { t, i18n } = useTranslation();
  const [filter, setFilter] = useState<AuditFilter>('');
  const audit = useAudit(filter);
  const system = useSystem();
  const locale = i18n.resolvedLanguage ?? 'en';
  // The browser's zone until the server's is known.
  const timeZone = system.data?.timeZone ?? '';
  const time = (iso: string) => formatZonedTime(iso, locale, timeZone);
  const first = audit.data?.pages[0];
  const entries = audit.data?.pages.flatMap((page) => page.entries) ?? [];

  const attacks = first?.recentWarnings ?? 0;
  const title =
    attacks > 0
      ? t('system.audit.titleWithAttacks', { title: t('system.audit.title'), count: attacks })
      : t('system.audit.title');

  const columns: Column<AuditEntry>[] = [
    {
      key: 'time',
      header: t('system.audit.time'),
      render: (entry) => {
        const mark = rowMark(entry);
        return (
          <div className={styles.timeCell}>
            {mark && (
              <StatePill tone={mark.tone}>
                <TriangleAlert size={14} aria-hidden="true" />
                {t(mark.labelKey)}
              </StatePill>
            )}
            <span>{time(entry.time)}</span>
          </div>
        );
      },
    },
    {
      key: 'event',
      header: t('system.audit.event'),
      render: (entry) => (
        <StatePill tone={entryTone(entry)}>
          {entry.count > 1
            ? t('system.audit.repeated', {
                event: t(`system.audit.types.${entry.type}`),
                count: entry.count,
              })
            : t(`system.audit.types.${entry.type}`)}
        </StatePill>
      ),
    },
    {
      key: 'ip',
      header: t('system.audit.ip'),
      render: (entry) => <span className={styles.mono}>{entry.clientIp || '—'}</span>,
    },
    {
      key: 'access',
      header: t('system.audit.access'),
      render: (entry) => t(`system.audit.accessKinds.${entry.access}`),
    },
  ];

  return (
    <Card title={title}>
      <div className={styles.form}>
        <p className={styles.secondary}>{t('system.audit.description')}</p>
        {first !== undefined && first.recentWarnings > 0 && (
          <Notice tone="danger" title={t('system.audit.warnings', { count: first.recentWarnings })}>
            {t('system.audit.warningsHint')}
          </Notice>
        )}
        {first?.newRemoteSignIn && (
          <Notice tone="warning" title={t('system.audit.newRemoteTitle')}>
            {t('system.audit.newRemote', {
              ip: first.newRemoteSignIn.clientIp,
              time: time(first.newRemoteSignIn.time),
            })}
          </Notice>
        )}
        <fieldset className={styles.radios}>
          <legend>{t('system.audit.show')}</legend>
          {FILTERS.map((option) => (
            <label key={option} className={styles.radio}>
              <input
                type="radio"
                name="auditFilter"
                value={option}
                checked={filter === option}
                onChange={() => setFilter(option)}
              />
              {t(`system.audit.filters.${option === '' ? 'all' : option}`)}
            </label>
          ))}
        </fieldset>
        {audit.isError && (
          <Notice tone="danger" role="alert">
            {genericErrorMessage(t, audit.error)}
          </Notice>
        )}
        {audit.isPending ? (
          <p aria-busy="true">{t('session.loading')}</p>
        ) : (
          <Table
            caption={t('system.audit.title')}
            columns={columns}
            rows={entries}
            rowKey={(entry) => String(entry.id)}
            emptyMessage={t('system.audit.empty')}
            rowClassName={(entry) => {
              const mark = rowMark(entry);
              if (mark?.kind === 'attack') {
                return styles.attackRow;
              }
              if (mark?.kind === 'failure') {
                return styles.failureRow;
              }
              return undefined;
            }}
            rowProps={(entry) => {
              const mark = rowMark(entry);
              return mark ? { 'data-severity': mark.kind } : undefined;
            }}
          />
        )}
        {audit.hasNextPage && (
          <div className={styles.buttons}>
            <Button
              loading={audit.isFetchingNextPage}
              onClick={() => {
                void audit.fetchNextPage();
              }}
            >
              {t('system.audit.older')}
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}
