import { lazy, Suspense } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, Route, Routes } from 'react-router';
import { Button } from '../components/Button';
import { AppShell } from '../layout/AppShell';
import { AuthLayout } from '../layout/AuthLayout';
import { Page } from '../layout/Page';
import styles from '../layout/AuthLayout.module.css';
import { LiveEvents } from '../live/LiveEvents';
import { DashboardPage } from '../pages/dashboard/DashboardPage';
import { LogPage } from '../pages/log/LogPage';
import { LoginPage } from '../pages/login/LoginPage';
import { ProfileFormPage } from '../pages/profiles/form/ProfileFormPage';
import { ProfilesPage } from '../pages/profiles/ProfilesPage';
import { SetupPage } from '../pages/setup/SetupPage';
import { SystemPage } from '../pages/system/SystemPage';
import { useSession } from './useSession';

// The firewall editor and the help texts are the largest pages; they load on first visit.
const FirewallPage = lazy(() =>
  import('../pages/firewall/FirewallPage').then((module) => ({ default: module.FirewallPage })),
);
const HelpPage = lazy(() =>
  import('../pages/help/HelpPage').then((module) => ({ default: module.HelpPage })),
);

function PageLoading({ title }: { title: string }) {
  const { t } = useTranslation();
  return (
    <Page title={title}>
      <p aria-busy="true">{t('session.loading')}</p>
    </Page>
  );
}

function FirewallLoading() {
  const { t } = useTranslation();
  return <PageLoading title={t('pages.firewall.title')} />;
}

function HelpLoading() {
  const { t } = useTranslation();
  return <PageLoading title={t('pages.help.title')} />;
}

function AppRoutes() {
  return (
    <LiveEvents>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="profiles" element={<ProfilesPage />} />
          <Route path="profiles/new" element={<ProfileFormPage />} />
          <Route path="profiles/:id" element={<ProfileFormPage />} />
          <Route
            path="firewall"
            element={
              <Suspense fallback={<FirewallLoading />}>
                <FirewallPage />
              </Suspense>
            }
          />
          <Route path="host-access" element={<Navigate to="/firewall" replace />} />
          <Route path="log" element={<LogPage />} />
          <Route path="system" element={<SystemPage />} />
          <Route
            path="help"
            element={
              <Suspense fallback={<HelpLoading />}>
                <HelpPage />
              </Suspense>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </LiveEvents>
  );
}

function ServerUnreachable({ retry, retrying }: { retry: () => void; retrying: boolean }) {
  const { t } = useTranslation();
  return (
    <AuthLayout title={t('session.unreachableTitle')}>
      <p className={styles.message}>{t('session.unreachableBody')}</p>
      <Button variant="primary" loading={retrying} onClick={retry}>
        {t('session.retry')}
      </Button>
    </AuthLayout>
  );
}

function Loading() {
  const { t } = useTranslation();
  return (
    <main className={styles.screen} aria-busy="true">
      <p className={styles.message}>{t('session.loading')}</p>
    </main>
  );
}

/** Chooses setup, login or the app from GET /api/session. */
export function SessionGate() {
  const session = useSession();

  if (session.isPending) {
    return <Loading />;
  }
  if (session.isError) {
    return <ServerUnreachable retry={() => void session.refetch()} retrying={session.isFetching} />;
  }
  if (session.data.setupRequired) {
    return <SetupPage />;
  }
  if (!session.data.authenticated) {
    return <LoginPage rememberAvailable={session.data.rememberAvailable} />;
  }
  return <AppRoutes />;
}
