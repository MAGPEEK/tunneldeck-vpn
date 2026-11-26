import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useNavigate } from 'react-router';
import { isApiError } from '../../api/client';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import { Notice } from '../../components/Notice';
import { Page } from '../../layout/Page';
import {
  useConnection,
  useConnectionControl,
  useFirewall,
  useFirewallDevices,
  useProfiles,
  useRemoteAccess,
  useSystem,
} from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { ImportFailureNotice } from '../profiles/import/ImportFailureNotice';
import { LoadProfileFileButton } from '../profiles/import/LoadProfileFileButton';
import { useProfileImport } from '../profiles/import/useProfileImport';
import { ConnectionCard, type ConnectionAction } from './ConnectionCard';
import styles from './DashboardPage.module.css';
import { useDashboardItems } from './dashboardItems';
import { StatusList } from './StatusList';

function actionErrorMessage(t: TFunction, error: unknown): string {
  if (isApiError(error) && error.code === 'conflict') {
    return t('connection.conflict');
  }
  if (isApiError(error) && error.code === 'not_found') {
    return t('connection.profileMissing');
  }
  return genericErrorMessage(t, error);
}

function useControls() {
  const control = useConnectionControl();
  const entries = Object.entries(control) as [ConnectionAction, (typeof control)['connect']][];
  const pending = entries.find(([, mutation]) => mutation.isPending)?.[0];
  const failed = entries.find(([, mutation]) => mutation.isError)?.[1].error;
  const reset = () => entries.forEach(([, mutation]) => mutation.reset());
  return { control, pending, failed, reset };
}

export function DashboardPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const profiles = useProfiles();
  const connection = useConnection();
  const firewall = useFirewall();
  const remoteAccess = useRemoteAccess();
  const devices = useFirewallDevices();
  const system = useSystem();
  const { control, pending, failed, reset } = useControls();
  const profileImport = useProfileImport();
  const items = useDashboardItems();

  if (profiles.isSuccess && profiles.data.length === 0) {
    return (
      <Page title={t('pages.dashboard.title')}>
        <div className={styles.stack}>
          {profileImport.failure && <ImportFailureNotice failure={profileImport.failure} />}
          <EmptyState
            title={t('dashboard.emptyTitle')}
            body={t('dashboard.emptyBody')}
            action={
              <div className={styles.emptyActions}>
                <LoadProfileFileButton
                  loading={profileImport.pending}
                  onFile={(file) => void profileImport.loadFile(file)}
                />
                <Button onClick={() => void navigate('/profiles/new')}>
                  {t('dashboard.createProfile')}
                </Button>
              </div>
            }
          />
        </div>
      </Page>
    );
  }

  const loadError = profiles.error ?? connection.error;
  const deviceCount = devices.data?.filter((device) => device.onLan).length;
  const activeProfile =
    profiles.data?.find((candidate) => candidate.id === connection.data?.profileId) ??
    profiles.data?.[0];
  return (
    <Page title={t('pages.dashboard.title')}>
      <div className={styles.stack}>
        {loadError && (
          <Notice tone="danger" role="alert">
            {genericErrorMessage(t, loadError)}
          </Notice>
        )}
        {connection.data && profiles.data && (
          <>
            <ConnectionCard
              status={connection.data}
              profiles={profiles.data}
              pending={pending}
              actionError={failed ? actionErrorMessage(t, failed) : undefined}
              onConnect={(profileId) => {
                reset();
                control.connect.mutate(profileId);
              }}
              onDisconnect={() => {
                reset();
                control.disconnect.mutate();
              }}
              onReconnect={() => {
                reset();
                control.reconnect.mutate();
              }}
              firewall={firewall.data}
              deviceCount={deviceCount}
              version={system.data?.version}
              showLine={items.isVisible('line')}
              details={(actions) => (
                <StatusList
                  status={connection.data}
                  firewall={firewall.data}
                  deviceCount={deviceCount}
                  remoteAccess={remoteAccess.data}
                  publicAddress={activeProfile?.publicAddress}
                  items={items}
                  footer={actions}
                />
              )}
            />
          </>
        )}
      </div>
    </Page>
  );
}
