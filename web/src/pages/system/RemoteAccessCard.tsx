import { useTranslation } from 'react-i18next';
import type { RemoteAccess } from '../../api/remoteAccess';
import { Card } from '../../components/Card';
import { Notice } from '../../components/Notice';
import { useConnection, useProfiles, useRemoteAccess } from '../../queries/queries';
import { RemoteAccessAddress } from '../../remoteAccess/RemoteAccessAddress';
import { remoteAccessActive, remoteAccessTarget } from '../../remoteAccess/remoteAccessUrl';
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
      {remoteAccessActive(remote.data) && remote.data && <RemoteAccessUrl remote={remote.data} />}
      {remote.data && <RemoteAccessForm saved={remote.data} />}
    </Card>
  );
}

/**
 * The URL remote access is reached at: the connected profile's public
 * address, else the detected public IP, else the VPN IP.
 */
function RemoteAccessUrl({ remote }: { remote: RemoteAccess }) {
  const { t } = useTranslation();
  const connection = useConnection();
  const profiles = useProfiles();
  const status = connection.data;
  const profile = profiles.data?.find((candidate) => candidate.id === status?.profileId);
  const connected = status?.state === 'connected';
  const target = remoteAccessTarget(
    remote.port,
    profile?.publicAddress,
    connected ? status.publicIp : undefined,
    connected ? status.vpnIp : undefined,
  );
  if (!target) {
    return null;
  }
  return (
    <dl className={styles.values}>
      <dt>{t('remoteAccess.url')}</dt>
      <dd>
        <RemoteAccessAddress target={target} profileId={profile?.id} />
      </dd>
    </dl>
  );
}
