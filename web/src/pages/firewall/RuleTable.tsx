import { ArrowDown, ArrowUp, Check } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { FirewallDirection } from '../../api/firewall';
import { Button } from '../../components/Button';
import { StatePill } from '../../components/StatePill';
import { Table, type Column } from '../../components/Table';
import styles from './FirewallPage.module.css';
import type { RuleDraft } from './ruleDraft';
import { protocolText, routeText, ruleName } from './ruleText';

export interface RuleTableProps {
  direction: FirewallDirection;
  /** The drafts of this direction in list order. */
  drafts: RuleDraft[];
  errorKeys: ReadonlySet<string>;
  onChange: (key: string, change: Partial<RuleDraft>) => void;
  onMove: (key: string, step: -1 | 1) => void;
  onEdit: (key: string) => void;
  onDuplicate: (key: string) => void;
  onDelete: (key: string) => void;
}

export function RuleTable(props: RuleTableProps) {
  const { direction, drafts, errorKeys, onChange, onMove, onEdit, onDuplicate, onDelete } = props;
  const { t } = useTranslation();
  const [confirmingKey, setConfirmingKey] = useState<string>();
  const inbound = direction === 'inbound';

  const columns: Column<RuleDraft>[] = [
    {
      key: 'order',
      header: <span className="visually-hidden">{t('firewall.column.order')}</span>,
      render: (draft) => {
        const index = drafts.indexOf(draft);
        const name = ruleName(t, draft);
        return (
          <div className={styles.order}>
            <Button
              variant="ghost"
              className={styles.iconButton}
              aria-label={t('firewall.moveUp', { name })}
              disabled={index === 0}
              onClick={() => onMove(draft.key, -1)}
            >
              <ArrowUp size={16} aria-hidden="true" />
            </Button>
            <Button
              variant="ghost"
              className={styles.iconButton}
              aria-label={t('firewall.moveDown', { name })}
              disabled={index === drafts.length - 1}
              onClick={() => onMove(draft.key, 1)}
            >
              <ArrowDown size={16} aria-hidden="true" />
            </Button>
          </div>
        );
      },
    },
    {
      key: 'enabled',
      header: t('firewall.column.enabled'),
      render: (draft) => (
        <input
          type="checkbox"
          className={styles.checkbox}
          aria-label={t('firewall.enabledNamed', { name: ruleName(t, draft) })}
          checked={draft.enabled}
          onChange={(event) => onChange(draft.key, { enabled: event.currentTarget.checked })}
        />
      ),
    },
    {
      key: 'name',
      header: t('firewall.column.name'),
      render: (draft) => (
        <div className={styles.nameCell}>
          <span>{ruleName(t, draft)}</span>
          {draft.highlighted && <StatePill>{t('firewall.unsaved')}</StatePill>}
          {errorKeys.has(draft.key) && (
            <StatePill tone="danger">{t('firewall.needsAttention')}</StatePill>
          )}
        </div>
      ),
    },
    {
      key: 'action',
      header: t('firewall.column.action'),
      render: (draft) => <StatePill>{t(`firewall.action.${draft.action}`)}</StatePill>,
    },
    {
      key: 'protocol',
      header: t('firewall.column.protocol'),
      render: (draft) => protocolText(t, draft),
    },
    {
      key: 'route',
      header: t('firewall.column.route'),
      render: (draft) => <span className={styles.mono}>{routeText(t, draft)}</span>,
    },
    ...(inbound
      ? [
          {
            key: 'keepSource',
            header: t('firewall.column.keepSource'),
            render: (draft: RuleDraft) =>
              draft.keepSourceAddress && draft.destinationKind === 'address' ? (
                <Check size={16} role="img" aria-label={t('firewall.keepSourceOn')} />
              ) : null,
          },
        ]
      : []),
    {
      key: 'actions',
      header: <span className="visually-hidden">{t('firewall.column.actions')}</span>,
      align: 'end',
      render: (draft) => {
        const name = ruleName(t, draft);
        return (
          <div className={styles.rowActions}>
            <Button
              variant="ghost"
              aria-label={t('firewall.editNamed', { name })}
              onClick={() => onEdit(draft.key)}
            >
              {t('firewall.edit')}
            </Button>
            <Button
              variant="ghost"
              aria-label={t('firewall.duplicateNamed', { name })}
              onClick={() => onDuplicate(draft.key)}
            >
              {t('firewall.duplicate')}
            </Button>
            <Button
              variant="ghost"
              aria-label={t('firewall.deleteNamed', { name })}
              onClick={() => setConfirmingKey(draft.key)}
            >
              {t('firewall.delete')}
            </Button>
          </div>
        );
      },
    },
  ];

  const confirmRow = (draft: RuleDraft) =>
    draft.key === confirmingKey ? (
      <div className={styles.confirm} role="group" aria-label={t('firewall.confirmLabel')}>
        <span>{t('firewall.confirmDelete', { name: ruleName(t, draft) })}</span>
        <div className={styles.rowActions}>
          <Button onClick={() => setConfirmingKey(undefined)}>{t('firewall.cancel')}</Button>
          <Button
            variant="danger"
            onClick={() => {
              setConfirmingKey(undefined);
              onDelete(draft.key);
            }}
          >
            {t('firewall.confirmDeleteButton')}
          </Button>
        </div>
      </div>
    ) : undefined;

  return (
    <Table
      columns={columns}
      rows={drafts}
      rowKey={(draft) => draft.key}
      rowDetail={confirmRow}
      rowState={(draft) => (draft.highlighted ? 'highlighted' : undefined)}
      caption={t(inbound ? 'firewall.tabs.inbound' : 'firewall.tabs.outbound')}
      emptyMessage={t(inbound ? 'firewall.emptyInbound' : 'firewall.emptyOutbound')}
    />
  );
}
