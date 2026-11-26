import { useTranslation } from 'react-i18next';
import type { FirewallState } from '../../api/firewall';
import { Notice } from '../../components/Notice';
import styles from './FirewallPage.module.css';

/** "Host: 192.168.2.10 · LAN: 192.168.2.0/24 · IP forwarding: on", a warning when off. */
export function HostContext({ state }: { state: FirewallState }) {
  const { t } = useTranslation();
  const notDetected = t('firewall.context.notDetected');
  const line = [
    t('firewall.context.host', { address: state.hostAddress || notDetected }),
    t('firewall.context.lan', { subnets: state.lanSubnets.join(', ') || notDetected }),
    t('firewall.context.ipForward', {
      state: t(state.ipForward ? 'firewall.context.on' : 'firewall.context.off'),
    }),
  ].join(' · ');
  if (state.ipForward) {
    return <p className={styles.secondary}>{line}</p>;
  }
  return (
    <Notice tone="warning" title={line}>
      <p>
        {t('firewall.context.ipForwardOff')}{' '}
        <a href={t('firewall.context.docsUrl')} target="_blank" rel="noreferrer">
          {t('firewall.context.docsLink')}
        </a>
      </p>
    </Notice>
  );
}
