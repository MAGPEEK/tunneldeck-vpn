import { ArrowDown, ArrowUp, Copy, Pencil, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { RuleCounters } from '../../api/firewall';
import { Button } from '../../components/Button';
import { StatePill } from '../../components/StatePill';
import styles from './FirewallPage.module.css';
import { FlowStrip } from './FlowStrip';
import { matchesFilter, type RuleDraft, type RuleFilter } from './ruleDraft';
import { ruleLine, ruleName, type RuleContext } from './ruleText';

const FILTERS: RuleFilter[] = ['all', 'inbound', 'outbound'];

export interface RuleListProps {
  /** Every draft in evaluation order. */
  drafts: RuleDraft[];
  filter: RuleFilter;
  onFilter: (filter: RuleFilter) => void;
  context: RuleContext;
  /** Hits by rule ID; `undefined` hides the counters. */
  counters: Record<string, RuleCounters> | undefined;
  errorKeys: ReadonlySet<string>;
  editingKey: string | undefined;
  onChange: (key: string, change: Partial<RuleDraft>) => void;
  onMove: (key: string, step: -1 | 1) => void;
  onEdit: (key: string) => void;
  onDuplicate: (key: string) => void;
  onDelete: (key: string) => void;
}

/** One list of all rules in evaluation order with filter chips (SPEC §16.4). */
export function RuleList(props: RuleListProps) {
  const { drafts, filter, onFilter } = props;
  const { t } = useTranslation();
  const [confirmingKey, setConfirmingKey] = useState<string>();
  const visible = drafts.filter((draft) => matchesFilter(draft, filter));

  return (
    <div className={styles.listBlock}>
      <div className={styles.filters} role="group" aria-label={t('firewall.filter.label')}>
        {FILTERS.map((option) => (
          <button
            key={option}
            type="button"
            className={styles.filterChip}
            aria-pressed={filter === option}
            onClick={() => onFilter(option)}
          >
            {t(`firewall.filter.${option}`)}
          </button>
        ))}
      </div>
      {visible.length === 0 ? (
        <p className={styles.secondary}>{t(`firewall.empty.${filter}`)}</p>
      ) : (
        <ol className={styles.rules} aria-label={t('firewall.listLabel')}>
          {visible.map((draft, index) => (
            <RuleRow
              key={draft.key}
              {...props}
              draft={draft}
              first={index === 0}
              last={index === visible.length - 1}
              confirming={confirmingKey === draft.key}
              onConfirm={setConfirmingKey}
            />
          ))}
        </ol>
      )}
    </div>
  );
}

interface RuleRowProps extends RuleListProps {
  draft: RuleDraft;
  first: boolean;
  last: boolean;
  confirming: boolean;
  onConfirm: (key: string | undefined) => void;
}

function RuleRow(props: RuleRowProps) {
  const { draft, context, errorKeys, editingKey, first, last, confirming, onConfirm } = props;
  const { t } = useTranslation();
  const name = ruleName(t, draft);
  return (
    <li
      className={styles.rule}
      data-state={draft.highlighted ? 'highlighted' : undefined}
      data-editing={editingKey === draft.key || undefined}
      aria-label={name}
    >
      <div className={styles.ruleMain}>
        <input
          type="checkbox"
          role="switch"
          className={styles.switch}
          aria-label={t('firewall.enabledNamed', { name })}
          checked={draft.enabled}
          onChange={(event) => props.onChange(draft.key, { enabled: event.currentTarget.checked })}
        />
        <div className={styles.ruleText}>
          <FlowStrip draft={draft} context={context} />
          <p className={styles.ruleLine}>
            <span>{ruleLine(t, draft, context)}</span>
            {draft.highlighted && <StatePill>{t('firewall.unsaved')}</StatePill>}
            {errorKeys.has(draft.key) && (
              <StatePill tone="danger">{t('firewall.needsAttention')}</StatePill>
            )}
          </p>
        </div>
        {props.counters !== undefined && <Hits draft={draft} counters={props.counters} />}
        <div className={styles.rowActions}>
          <Button
            variant="ghost"
            className={styles.iconButton}
            aria-label={t('firewall.moveUp', { name })}
            disabled={first}
            onClick={() => props.onMove(draft.key, -1)}
          >
            <ArrowUp size={16} aria-hidden="true" />
          </Button>
          <Button
            variant="ghost"
            className={styles.iconButton}
            aria-label={t('firewall.moveDown', { name })}
            disabled={last}
            onClick={() => props.onMove(draft.key, 1)}
          >
            <ArrowDown size={16} aria-hidden="true" />
          </Button>
          <Button
            variant="secondary"
            size="small"
            icon={<Pencil size={16} aria-hidden="true" />}
            aria-label={t('firewall.editNamed', { name })}
            onClick={() => props.onEdit(draft.key)}
          >
            {t('firewall.edit')}
          </Button>
          <Button
            variant="secondary"
            size="small"
            icon={<Copy size={16} aria-hidden="true" />}
            aria-label={t('firewall.duplicateNamed', { name })}
            onClick={() => props.onDuplicate(draft.key)}
          >
            {t('firewall.duplicate')}
          </Button>
          <Button
            variant="danger"
            size="small"
            icon={<Trash2 size={16} aria-hidden="true" />}
            aria-label={t('firewall.deleteNamed', { name })}
            onClick={() => onConfirm(draft.key)}
          >
            {t('firewall.delete')}
          </Button>
        </div>
      </div>
      {confirming && (
        <div className={styles.confirm} role="group" aria-label={t('firewall.confirmLabel')}>
          <span>{t('firewall.confirmDelete', { name })}</span>
          <div className={styles.rowActions}>
            <Button onClick={() => onConfirm(undefined)}>{t('firewall.cancel')}</Button>
            <Button
              variant="danger"
              onClick={() => {
                onConfirm(undefined);
                props.onDelete(draft.key);
              }}
            >
              {t('firewall.confirmDeleteButton')}
            </Button>
          </div>
        </div>
      )}
    </li>
  );
}

/** "N hits"; "–" while the rule is off or not saved yet. */
function Hits({ draft, counters }: { draft: RuleDraft; counters: Record<string, RuleCounters> }) {
  const { t } = useTranslation();
  if (!draft.enabled || draft.id === '') {
    return (
      <span className={styles.hits}>
        <span aria-hidden="true">–</span>
        <span className="visually-hidden">{t('firewall.hitsNone')}</span>
      </span>
    );
  }
  const count = counters[draft.id]?.packets ?? 0;
  return <span className={styles.hits}>{t('firewall.hits', { count })}</span>;
}
