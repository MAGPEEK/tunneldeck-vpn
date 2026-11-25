import { CircleCheck, CircleX } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { CheckResult } from '../../api/system';
import { Card } from '../../components/Card';
import { translateDynamic } from '../../i18n/dynamic';
import styles from './SystemPage.module.css';

export function SelfCheckCard({ checks }: { checks: CheckResult[] }) {
  const { t } = useTranslation();
  return (
    <Card title={t('system.selfCheckTitle')}>
      {checks.length === 0 ? (
        <p className={styles.secondary}>{t('system.noChecks')}</p>
      ) : (
        <ul className={styles.checks}>
          {checks.map((check) => {
            const Icon = check.ok ? CircleCheck : CircleX;
            return (
              <li key={check.id} className={styles.check}>
                <Icon
                  size={16}
                  className={`${styles.checkIcon} ${check.ok ? styles.pass : styles.fail}`}
                  aria-label={check.ok ? t('system.checkPassed') : t('system.checkFailed')}
                  role="img"
                />
                <div className={styles.checkText}>
                  <span>{translateDynamic(t, `system.check.${check.id}`, check.id)}</span>
                  {check.detail && <span className={styles.secondary}>{check.detail}</span>}
                  {!check.ok && (
                    <span className={styles.danger}>
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
