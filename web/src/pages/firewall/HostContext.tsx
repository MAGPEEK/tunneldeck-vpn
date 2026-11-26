import { useTranslation } from 'react-i18next';
import type { FirewallState } from '../../api/firewall';
import { Notice } from '../../components/Notice';
import type { Language } from '../../i18n';
import { useSystem } from '../../queries/queries';
import { docUrl } from '../help/links';
import styles from './FirewallPage.module.css';

/** "This device: 192.168.1.10 · Local LAN: 192.168.1.0/24 · IP forwarding: on", a warning when off. */
export function HostContext({ state }: { state: FirewallState }) {
  const { t, i18n } = useTranslation();
  const language: Language = i18n.resolvedLanguage === 'de' ? 'de' : 'en';
  const version = useSystem().data?.version;
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
        <a
          href={`${docUrl('linux', version, language)}#${t('firewall.context.docsAnchor')}`}
          target="_blank"
          rel="noreferrer"
        >
          {t('firewall.context.docsLink')}
        </a>
      </p>
    </Notice>
  );
}
