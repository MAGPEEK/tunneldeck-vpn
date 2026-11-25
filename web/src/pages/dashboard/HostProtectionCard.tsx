import { ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { HostAccessRule } from '../../api/hostAccess';
import type { RemoteAccess } from '../../api/remoteAccess';
import { Card } from '../../components/Card';
import styles from './HostProtectionCard.module.css';

export interface HostProtectionCardProps {
  rules: HostAccessRule[] | undefined;
  remoteAccess: RemoteAccess | null | undefined;
}

export function HostProtectionCard({ rules, remoteAccess }: HostProtectionCardProps) {
  const { t } = useTranslation();
  const open = (rules ?? []).filter((rule) => rule.enabled);
  const list = open.map((rule) => `${rule.protocol.toUpperCase()} ${rule.port}`).join(', ');
  return (
    <Card>
      <div className={styles.row}>
        <ShieldCheck size={20} aria-hidden="true" className={styles.icon} />
        <div className={styles.text}>
          <h2 className={styles.title}>{t('hostProtection.title')}</h2>
          {rules !== undefined && (
            <p className={styles.sub}>
              {open.length === 0
                ? t('hostProtection.noPorts')
                : t('hostProtection.openPorts', { count: open.length, list })}
            </p>
          )}
          {remoteAccess?.enabled && (
            <p className={styles.sub}>
              {t('hostProtection.remoteAccess', { port: remoteAccess.port })}
            </p>
          )}
        </div>
        <Link to="/host-access" className={styles.link}>
          {t('hostProtection.manage')}
        </Link>
      </div>
    </Card>
  );
}
