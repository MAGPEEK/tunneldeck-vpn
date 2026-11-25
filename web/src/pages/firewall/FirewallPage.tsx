import { useTranslation } from 'react-i18next';
import { Notice } from '../../components/Notice';
import { Page } from '../../layout/Page';
import { useFirewall } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { FirewallEditor } from './FirewallEditor';

export function FirewallPage() {
  const { t } = useTranslation();
  const firewall = useFirewall();
  if (firewall.data) {
    return <FirewallEditor saved={firewall.data} />;
  }
  return (
    <Page title={t('pages.firewall.title')}>
      <p>{t('firewall.explanation')}</p>
      {firewall.isError && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, firewall.error)}
        </Notice>
      )}
      {firewall.isPending && <p aria-busy="true">{t('session.loading')}</p>}
    </Page>
  );
}
