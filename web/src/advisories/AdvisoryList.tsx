import { Info, OctagonExclamationPoint, TriangleExclamationPoint } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { Advisory, AdvisorySeverity } from '../api/profiles';
import { Notice } from '../components/Notice';
import { translateDynamic } from '../i18n/dynamic';
import styles from './AdvisoryList.module.css';

const ICONS = {
  info: Info,
  warning: TriangleExclamationPoint,
  danger: OctagonExclamationPoint,
} as const;

const SEVERITY_ORDER: Record<AdvisorySeverity, number> = { danger: 0, warning: 1, info: 2 };

/** Advisories ordered danger first, keeping the server order within a severity. */
function sortAdvisories(advisories: readonly Advisory[]): Advisory[] {
  return [...advisories].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

function useAdvisoryText() {
  const { t } = useTranslation();
  return (advisory: Advisory) =>
    translateDynamic(
      t,
      `advisory.${advisory.code}`,
      t('advisory.unknown', { code: advisory.code }),
    );
}

/** Compact list: icon and text per advisory, coloured by severity. */
export function AdvisoryList({ advisories }: { advisories: readonly Advisory[] }) {
  const { t } = useTranslation();
  const text = useAdvisoryText();
  if (advisories.length === 0) {
    return null;
  }
  return (
    <ul className={styles.list} aria-label={t('advisory.listLabel')}>
      {sortAdvisories(advisories).map((advisory) => {
        const Icon = ICONS[advisory.severity];
        return (
          <li
            key={`${advisory.code}-${advisory.field ?? ''}`}
            className={`${styles.item} ${styles[advisory.severity]}`}
            data-severity={advisory.severity}
          >
            <Icon size={14} aria-hidden="true" className={styles.icon} />
            <span>{text(advisory)}</span>
          </li>
        );
      })}
    </ul>
  );
}

/**
 * The advisories of a saved profile above its form. Danger findings get a
 * notice of their own so they cannot be overlooked.
 */
export function AdvisoryNotice({ advisories }: { advisories: readonly Advisory[] }) {
  const { t } = useTranslation();
  const text = useAdvisoryText();
  const danger = advisories.filter((advisory) => advisory.severity === 'danger');
  const others = advisories.filter((advisory) => advisory.severity !== 'danger');
  return (
    <>
      {danger.map((advisory) => (
        <Notice
          key={`${advisory.code}-${advisory.field ?? ''}`}
          tone="danger"
          title={translateDynamic(t, `advisory.title.${advisory.code}`, t('advisory.dangerTitle'))}
        >
          <p>{text(advisory)}</p>
        </Notice>
      ))}
      {others.length > 0 && (
        <Notice tone="info" title={t('advisory.noticeTitle')}>
          <AdvisoryList advisories={others} />
        </Notice>
      )}
    </>
  );
}
