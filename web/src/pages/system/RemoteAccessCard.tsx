import { useTranslation } from 'react-i18next';
import { Card } from '../../components/Card';
import { Notice } from '../../components/Notice';
import { useRemoteAccess } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { RemoteAccessForm } from './RemoteAccessForm';
import styles from './SystemPage.module.css';

/** SPEC §8.1: HTTPS listener for reaching the UI over the tunnel. */
export function RemoteAccessCard() {
  const { t } = useTranslation();
  const remote = useRemoteAccess();
  return (
    <Card title={t('remoteAccess.title')}>
      {remote.isPending && <p aria-busy="true">{t('session.loading')}</p>}
      {remote.isError && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, remote.error)}
        </Notice>
      )}
      {remote.data === null && <p className={styles.secondary}>{t('remoteAccess.unavailable')}</p>}
      {remote.data && <RemoteAccessForm saved={remote.data} />}
    </Card>
  );
}
