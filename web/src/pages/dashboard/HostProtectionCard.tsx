import { ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { targetsHost, type FirewallState } from '../../api/firewall';
import type { RemoteAccess } from '../../api/remoteAccess';
import { Card } from '../../components/Card';
import styles from './HostProtectionCard.module.css';

export interface HostProtectionCardProps {
  firewall: FirewallState | undefined;
  remoteAccess: RemoteAccess | null | undefined;
}

/** Whether an enabled rule needs IP forwarding: a port forward or an outbound rule. */
function needsForwarding(firewall: FirewallState): boolean {
  return firewall.rules.some(
    (rule) =>
      rule.enabled &&
      (rule.direction === 'outbound' || !targetsHost(rule.destination, firewall.hostAddresses)),
  );
}

export function HostProtectionCard({ firewall, remoteAccess }: HostProtectionCardProps) {
  const { t } = useTranslation();
  const count = (direction: string) =>
    firewall?.rules.filter((rule) => rule.direction === direction).length ?? 0;
  return (
    <Card>
      <div className={styles.row}>
        <ShieldCheck size={20} aria-hidden="true" className={styles.icon} />
        <div className={styles.text}>
          <h2 className={styles.title}>{t('hostProtection.title')}</h2>
          {firewall !== undefined && (
            <p className={styles.sub}>
              {t('hostProtection.inboundRules', { count: count('inbound') })},{' '}
              {t('hostProtection.outboundRules', { count: count('outbound') })}
            </p>
          )}
          {firewall !== undefined && !firewall.ipForward && needsForwarding(firewall) && (
            <p className={styles.warning}>{t('hostProtection.ipForwardOff')}</p>
          )}
          {remoteAccess?.enabled && (
            <p className={styles.sub}>
              {t('hostProtection.remoteAccess', { port: remoteAccess.port })}
            </p>
          )}
        </div>
        <Link to="/firewall" className={styles.link}>
          {t('hostProtection.manage')}
        </Link>
      </div>
    </Card>
  );
}
