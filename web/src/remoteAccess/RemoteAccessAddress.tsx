import { useTranslation } from 'react-i18next';
import type { RemoteAccessTarget } from './remoteAccessUrl';
import styles from './RemoteAccessAddress.module.css';

/** The remote access URL as a link, and a hint when it falls back to the VPN IP. */
export function RemoteAccessAddress({ target }: { target: RemoteAccessTarget }) {
  const { t } = useTranslation();
  return (
    <span className={styles.address}>
      <a href={target.url} className={styles.url} target="_blank" rel="noreferrer">
        {target.url}
      </a>
      {target.fromVpnIp && <span className={styles.hint}>{t('remoteAccess.vpnIpHint')}</span>}
    </span>
  );
}
