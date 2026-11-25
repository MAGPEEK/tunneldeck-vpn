import { useTranslation } from 'react-i18next';
import { Notice } from '../../components/Notice';
import { Page } from '../../layout/Page';
import { useHostAccess } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { HostAccessEditor } from './HostAccessEditor';

export function HostAccessPage() {
  const { t } = useTranslation();
  const rules = useHostAccess();
  return (
    <Page title={t('pages.hostAccess.title')}>
      <p>{t('hostAccess.explanation')}</p>
      {rules.isError && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, rules.error)}
        </Notice>
      )}
      {rules.isPending && <p aria-busy="true">{t('session.loading')}</p>}
      {rules.data && <HostAccessEditor saved={rules.data} />}
    </Page>
  );
}
