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
  useLogs,
  useProfiles,
  useRemoteAccess,
} from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { ConnectionCard, type ConnectionAction } from './ConnectionCard';
import styles from './DashboardPage.module.css';
import { HostProtectionCard } from './HostProtectionCard';
import { LogCard } from './LogCard';
import { MetricRow } from './MetricRow';

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
  const logs = useLogs();
  const { control, pending, failed, reset } = useControls();

  if (profiles.isSuccess && profiles.data.length === 0) {
    return (
      <Page title={t('pages.dashboard.title')}>
        <EmptyState
          title={t('dashboard.emptyTitle')}
          body={t('dashboard.emptyBody')}
          action={
            <Button variant="primary" onClick={() => void navigate('/profiles/new')}>
              {t('dashboard.createProfile')}
            </Button>
          }
        />
      </Page>
    );
  }

  const loadError = profiles.error ?? connection.error;
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
            />
            <MetricRow status={connection.data} />
          </>
        )}
        <HostProtectionCard firewall={firewall.data} remoteAccess={remoteAccess.data} />
        <LogCard lines={logs.data} />
      </div>
    </Page>
  );
}
