import { useTranslation } from 'react-i18next';
import { Notice } from '../../components/Notice';
import { Page } from '../../layout/Page';
import { useSystem } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { RemoteAccessCard } from './RemoteAccessCard';
import { SelfCheckCard } from './SelfCheckCard';
import styles from './SystemPage.module.css';
import { VersionCard } from './VersionCard';

export function SystemPage() {
  const { t } = useTranslation();
  const system = useSystem();
  return (
    <Page title={t('pages.system.title')}>
      <div className={styles.stack}>
        {system.isError && (
          <Notice tone="danger" role="alert">
            {genericErrorMessage(t, system.error)}
          </Notice>
        )}
        {system.data && (
          <>
            <VersionCard system={system.data} />
            <SelfCheckCard checks={system.data.checks} />
          </>
        )}
        <RemoteAccessCard />
      </div>
    </Page>
  );
}
