import { useTranslation } from 'react-i18next';
import { Page } from '../../layout/Page';
import { useLogs } from '../../queries/queries';
import { LogCard } from './LogCard';

/** The live log of the VPN connection; new lines arrive through the event stream. */
export function LogPage() {
  const { t } = useTranslation();
  const logs = useLogs();
  return (
    <Page title={t('pages.log.title')}>
      <LogCard lines={logs.data} />
    </Page>
  );
}
