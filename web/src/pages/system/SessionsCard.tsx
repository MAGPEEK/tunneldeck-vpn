import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Notice } from '../../components/Notice';
import { useLogoutEverywhere } from '../../session/useSession';
import { genericErrorMessage } from '../auth/formError';
import styles from './SystemPage.module.css';

export function SessionsCard() {
  const { t } = useTranslation();
  const logoutEverywhere = useLogoutEverywhere();
  const [confirming, setConfirming] = useState(false);
  return (
    <Card title={t('system.sessions.title')}>
      <div className={styles.form}>
        <p className={styles.secondary}>{t('system.sessions.description')}</p>
        {logoutEverywhere.isError && (
          <Notice tone="danger" role="alert">
            {genericErrorMessage(t, logoutEverywhere.error)}
          </Notice>
        )}
        {confirming ? (
          <div
            className={styles.confirm}
            role="group"
            aria-label={t('system.sessions.confirmLabel')}
          >
            <span>{t('system.sessions.confirm')}</span>
            <div className={styles.buttons}>
              <Button onClick={() => setConfirming(false)}>{t('system.sessions.cancel')}</Button>
              <Button
                variant="danger"
                loading={logoutEverywhere.isPending}
                onClick={() => logoutEverywhere.mutate()}
              >
                {t('system.sessions.signOutEverywhere')}
              </Button>
            </div>
          </div>
        ) : (
          <div className={styles.buttons}>
            <Button onClick={() => setConfirming(true)}>
              {t('system.sessions.signOutEverywhere')}
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
}
