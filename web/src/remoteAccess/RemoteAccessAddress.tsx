import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { RemoteAccessTarget } from './remoteAccessUrl';
import styles from './RemoteAccessAddress.module.css';

interface RemoteAccessAddressProps {
  target: RemoteAccessTarget;
  /** The connected profile, linked from the hint where its public address is set. */
  profileId?: string;
}

/** The remote access URL as a link, and a hint when it falls back to the VPN IP. */
export function RemoteAccessAddress({ target, profileId }: RemoteAccessAddressProps) {
  const { t } = useTranslation();
  return (
    <span className={styles.address}>
      <a href={target.url} className={styles.url} target="_blank" rel="noreferrer">
        {target.url}
      </a>
      {target.fromVpnIp && (
        <span className={styles.hint}>
          {t('remoteAccess.vpnIpHint')}{' '}
          {profileId && <Link to={`/profiles/${profileId}`}>{t('remoteAccess.editProfile')}</Link>}
        </span>
      )}
    </span>
  );
}
