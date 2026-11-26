import { useTranslation } from 'react-i18next';
import { CopyButton } from '../components/CopyButton';
import type { RemoteAccessTarget } from './remoteAccessUrl';
import styles from './RemoteAccessAddress.module.css';

/** The remote access URL as a link with a Copy button, and a hint when it falls back to the VPN IP. */
export function RemoteAccessAddress({ target }: { target: RemoteAccessTarget }) {
  const { t } = useTranslation();
  return (
    <span className={styles.address}>
      <span className={styles.line}>
        <a href={target.url} className={styles.url} target="_blank" rel="noreferrer">
          {target.url}
        </a>
        <CopyButton text={target.url} />
      </span>
      {target.fromVpnIp && <span className={styles.hint}>{t('remoteAccess.vpnIpHint')}</span>}
    </span>
  );
}
