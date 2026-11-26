import { CircleCheck, CircleX, TriangleAlert } from 'lucide-react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { CheckResult } from '../../api/system';
import { Card } from '../../components/Card';
import { translateDynamic } from '../../i18n/dynamic';
import styles from './SystemPage.module.css';

/** Icon, tone and label of a check: passed, failed, or a warning (failed, feature off). */
function checkState(t: TFunction, check: CheckResult) {
  if (check.ok) {
    return {
      Icon: CircleCheck,
      iconClass: styles.pass,
      label: t('system.checkPassed'),
    };
  }
  if (check.warning) {
    return {
      Icon: TriangleAlert,
      iconClass: styles.warn,
      label: t('system.checkWarning'),
    };
  }
  return {
    Icon: CircleX,
    iconClass: styles.fail,
    label: t('system.checkFailed'),
  };
}

/** The detail translated by its code; the server's English detail for an unknown code. */
function detailText(t: TFunction, check: CheckResult): string {
  if (!check.detailCode) {
    return check.detail;
  }
  return translateDynamic(t, `system.detail.${check.detailCode}`, check.detail, check.params);
}

function CheckEntry({ check }: { check: CheckResult }) {
  const { t } = useTranslation();
  const { Icon, iconClass, label } = checkState(t, check);
  const detail = detailText(t, check);
  return (
    <li className={styles.check}>
      <div className={styles.checkHead}>
        <Icon
          size={16}
          className={`${styles.checkIcon} ${iconClass}`}
          aria-label={label}
          role="img"
        />
        <span className={styles.checkTitle}>
          {translateDynamic(t, `system.check.${check.id}`, check.id)}
        </span>
      </div>
      {detail !== '' && <p className={styles.checkLine}>{detail}</p>}
      {!check.ok && (
        <p className={`${styles.checkLine} ${styles.secondary}`}>
          {translateDynamic(t, `system.hint.${check.id}`, check.hint ?? '')}
        </p>
      )}
    </li>
  );
}

export function SelfCheckCard({ checks }: { checks: CheckResult[] }) {
  const { t } = useTranslation();
  return (
    <Card title={t('system.selfCheckTitle')}>
      {checks.length === 0 ? (
        <p className={styles.secondary}>{t('system.noChecks')}</p>
      ) : (
        <ul className={styles.checks}>
          {checks.map((check) => (
            <CheckEntry key={check.id} check={check} />
          ))}
        </ul>
      )}
    </Card>
  );
}
