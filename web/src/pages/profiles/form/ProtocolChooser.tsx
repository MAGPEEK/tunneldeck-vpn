import { useTranslation } from 'react-i18next';
import { StatePill } from '../../../components/StatePill';
import { protocolName } from '../profileText';
import styles from './ProfileForm.module.css';

/** Protocols shown in the chooser; those without a driver are planned. */
const PROTOCOLS = ['openvpn', 'wireguard', 'ipsec'] as const;

export interface ProtocolChooserProps {
  available: readonly string[];
  value: string;
  onChange: (protocol: string) => void;
}

export function ProtocolChooser({ available, value, onChange }: ProtocolChooserProps) {
  const { t } = useTranslation();
  return (
    <fieldset className={styles.protocols}>
      <legend className={styles.legend}>{t('profileForm.protocol')}</legend>
      {PROTOCOLS.map((protocol) => {
        const enabled = available.includes(protocol);
        return (
          <label key={protocol} className={styles.protocol} data-disabled={!enabled || undefined}>
            <input
              type="radio"
              name="protocol"
              value={protocol}
              checked={value === protocol}
              disabled={!enabled}
              onChange={() => onChange(protocol)}
            />
            <span>{protocolName(t, protocol)}</span>
            {!enabled && <StatePill>{t('profileForm.planned')}</StatePill>}
          </label>
        );
      })}
    </fieldset>
  );
}
