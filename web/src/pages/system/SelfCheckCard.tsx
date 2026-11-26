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
      textClass: '',
      label: t('system.checkPassed'),
    };
  }
  if (check.warning) {
    return {
      Icon: TriangleAlert,
      iconClass: styles.warn,
      textClass: styles.warnText,
      label: t('system.checkWarning'),
    };
  }
  return {
    Icon: CircleX,
    iconClass: styles.fail,
    textClass: styles.danger,
    label: t('system.checkFailed'),
  };
}

export function SelfCheckCard({ checks }: { checks: CheckResult[] }) {
  const { t } = useTranslation();
  return (
    <Card title={t('system.selfCheckTitle')}>
      {checks.length === 0 ? (
        <p className={styles.secondary}>{t('system.noChecks')}</p>
      ) : (
        <ul className={styles.checks}>
          {checks.map((check) => {
            const { Icon, iconClass, textClass, label } = checkState(t, check);
            return (
              <li key={check.id} className={styles.check}>
                <Icon
                  size={16}
                  className={`${styles.checkIcon} ${iconClass}`}
                  aria-label={label}
                  role="img"
                />
                <div className={styles.checkText}>
                  <span>{translateDynamic(t, `system.check.${check.id}`, check.id)}</span>
                  {check.detail && <span className={styles.secondary}>{check.detail}</span>}
                  {!check.ok && (
                    <span className={textClass}>
                      {translateDynamic(t, `system.hint.${check.id}`, check.hint ?? '')}
                    </span>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
