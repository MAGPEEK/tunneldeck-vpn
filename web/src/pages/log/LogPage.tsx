import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router';
import { Tabs } from '../../components/Tabs';
import { Page } from '../../layout/Page';
import { useLogs } from '../../queries/queries';
import type { HelpSectionId } from '../help/content';
import { HelpLink } from '../help/HelpLink';
import { AuditCard } from '../system/AuditCard';
import { LogCard } from './LogCard';

/** The query-param value that selects the sign-ins tab; its absence shows the VPN log. */
const SIGN_INS = 'sign-ins';

/**
 * Gathers the logs in one place: the live VPN tunnel protocol and, on a second
 * tab, the sign-in and attack audit log. The selected tab lives in the URL
 * (`?tab=sign-ins`) so it is linkable and survives the back button.
 */
export function LogPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const logs = useLogs();
  const signIns = params.get('tab') === SIGN_INS;
  const active = signIns ? SIGN_INS : 'vpn';
  const help: HelpSectionId = signIns ? 'sign-ins' : 'troubleshooting';

  const tabs = [
    { id: 'vpn', label: t('log.tabs.vpn') },
    { id: SIGN_INS, label: t('log.tabs.signIns') },
  ];

  const select = (id: string) => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (id === SIGN_INS) {
          next.set('tab', SIGN_INS);
        } else {
          next.delete('tab');
        }
        return next;
      },
      { replace: true },
    );
  };

  return (
    <Page title={t('pages.log.title')} actions={<HelpLink section={help} />}>
      <Tabs label={t('log.tabs.label')} tabs={tabs} active={active} onChange={select}>
        {signIns ? <AuditCard /> : <LogCard lines={logs.data} />}
      </Tabs>
    </Page>
  );
}
