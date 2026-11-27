import { useTranslation } from 'react-i18next';
import { Notice } from '../../components/Notice';
import { Page } from '../../layout/Page';
import { useSystem } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { HelpLink } from '../help/HelpLink';
import { AuditCard } from './AuditCard';
import { PublicIpLookupCard } from './PublicIpLookupCard';
import { RemoteAccessCard } from './RemoteAccessCard';
import { SelfCheckCard } from './SelfCheckCard';
import { SessionsCard } from './SessionsCard';
import styles from './SystemPage.module.css';
import { VersionCard } from './VersionCard';

export function SystemPage() {
  const { t } = useTranslation();
  const system = useSystem();
  return (
    <Page title={t('pages.system.title')} actions={<HelpLink section="system-checks" />}>
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
        <PublicIpLookupCard />
        <AuditCard />
        <SessionsCard />
      </div>
    </Page>
  );
}
