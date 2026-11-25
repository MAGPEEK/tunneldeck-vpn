import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, X } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import { putHostAccess, type HostAccessRule, type Transport } from '../../api/hostAccess';
import { queryKeys } from '../../api/queryKeys';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import fieldStyles from '../../components/Field.module.css';
import { Notice } from '../../components/Notice';
import { Table, type Column } from '../../components/Table';
import { genericErrorMessage } from '../auth/formError';
import styles from './HostAccessPage.module.css';
import { newRow, rowErrors, rowsDiffer, toRows, toRules, type RuleRow } from './ruleRows';

const TRANSPORTS: Transport[] = ['tcp', 'udp'];

export function HostAccessEditor({ saved }: { saved: HostAccessRule[] }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [rows, setRows] = useState(() => toRows(saved));
  const save = useMutation({
    mutationFn: putHostAccess,
    onSuccess: (rules) => {
      client.setQueryData(queryKeys.hostAccess, rules);
      setRows(toRows(rules));
    },
  });
  const dirty = rowsDiffer(rows, saved);
  const fields = isApiError(save.error) ? save.error.fields : {};

  const update = (key: string, change: Partial<RuleRow>) =>
    setRows((current) => current.map((row) => (row.key === key ? { ...row, ...change } : row)));
  const remove = (key: string) => setRows((current) => current.filter((row) => row.key !== key));
  const indexOf = (row: RuleRow) => rows.indexOf(row);
  const label = (name: string, row: RuleRow) =>
    t('hostAccess.cellLabel', { name, number: indexOf(row) + 1 });
  const errorFor = (row: RuleRow, name: string) => rowErrors(fields, indexOf(row))[name];

  const columns: Column<RuleRow>[] = [
    {
      key: 'protocol',
      header: t('hostAccess.protocol'),
      render: (row) => (
        <select
          className={`${fieldStyles.control} ${styles.protocol}`}
          aria-label={label(t('hostAccess.protocol'), row)}
          value={row.protocol}
          onChange={(event) =>
            update(row.key, { protocol: event.currentTarget.value as Transport })
          }
        >
          {TRANSPORTS.map((transport) => (
            <option key={transport} value={transport}>
              {transport.toUpperCase()}
            </option>
          ))}
        </select>
      ),
    },
    {
      key: 'port',
      header: t('hostAccess.port'),
      render: (row) => (
        <Cell error={errorFor(row, 'port')}>
          <input
            className={`${fieldStyles.control} ${styles.port}`}
            type="number"
            min={1}
            max={65535}
            inputMode="numeric"
            aria-label={label(t('hostAccess.port'), row)}
            aria-invalid={errorFor(row, 'port') ? true : undefined}
            value={row.port}
            onChange={(event) => update(row.key, { port: event.currentTarget.value })}
          />
        </Cell>
      ),
    },
    {
      key: 'source',
      header: t('hostAccess.source'),
      render: (row) => (
        <Cell error={errorFor(row, 'sourceCidr')}>
          <input
            className={`${fieldStyles.control} ${styles.mono}`}
            placeholder="203.0.113.0/24"
            aria-label={label(t('hostAccess.source'), row)}
            aria-invalid={errorFor(row, 'sourceCidr') ? true : undefined}
            value={row.sourceCidr}
            spellCheck={false}
            onChange={(event) => update(row.key, { sourceCidr: event.currentTarget.value })}
          />
        </Cell>
      ),
    },
    {
      key: 'enabled',
      header: t('hostAccess.enabled'),
      render: (row) => (
        <input
          type="checkbox"
          className={styles.checkbox}
          aria-label={label(t('hostAccess.enabled'), row)}
          checked={row.enabled}
          onChange={(event) => update(row.key, { enabled: event.currentTarget.checked })}
        />
      ),
    },
    {
      key: 'comment',
      header: t('hostAccess.comment'),
      render: (row) => (
        <Cell error={errorFor(row, 'comment')}>
          <input
            className={fieldStyles.control}
            aria-label={label(t('hostAccess.comment'), row)}
            value={row.comment}
            onChange={(event) => update(row.key, { comment: event.currentTarget.value })}
          />
        </Cell>
      ),
    },
    {
      key: 'remove',
      header: <span className="visually-hidden">{t('hostAccess.actions')}</span>,
      align: 'end',
      render: (row) => (
        <Button
          variant="ghost"
          aria-label={t('hostAccess.removeRule', { number: indexOf(row) + 1 })}
          onClick={() => remove(row.key)}
        >
          <X size={16} aria-hidden="true" />
        </Button>
      ),
    },
  ];

  const failure = save.error;
  return (
    <>
      {isApiError(failure) && failure.code === 'firewall_failed' && (
        <Notice tone="danger" role="alert" title={t('hostAccess.firewallFailedTitle')}>
          <p>{t('hostAccess.firewallFailed')}</p>
        </Notice>
      )}
      {failure &&
        !(
          isApiError(failure) && ['firewall_failed', 'validation_failed'].includes(failure.code)
        ) && (
          <Notice tone="danger" role="alert">
            {genericErrorMessage(t, failure)}
          </Notice>
        )}
      {isApiError(failure) && failure.code === 'validation_failed' && (
        <Notice tone="danger" role="alert">
          {t('hostAccess.invalid')}
        </Notice>
      )}
      {save.isSuccess && !dirty && (
        <Notice tone="info" role="status">
          {t('hostAccess.saved')}
        </Notice>
      )}
      <Card>
        <div className={styles.body}>
          <Table
            columns={columns}
            rows={rows}
            rowKey={(row) => row.key}
            caption={t('pages.hostAccess.title')}
            emptyMessage={t('hostAccess.empty')}
          />
          <div className={styles.buttons}>
            <Button
              icon={<Plus size={16} aria-hidden="true" />}
              onClick={() => setRows([...rows, newRow()])}
            >
              {t('hostAccess.addRule')}
            </Button>
            <Button
              variant="primary"
              disabled={!dirty}
              loading={save.isPending}
              onClick={() => save.mutate(toRules(rows))}
            >
              {t('hostAccess.save')}
            </Button>
          </div>
        </div>
      </Card>
    </>
  );
}

function Cell({ error, children }: { error: string | undefined; children: ReactNode }) {
  return (
    <div className={styles.cell}>
      {children}
      {error && <p className={fieldStyles.error}>{error}</p>}
    </div>
  );
}
