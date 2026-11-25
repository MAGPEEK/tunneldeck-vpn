import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import type { FirewallSettings } from '../../api/firewall';
import { Card } from '../../components/Card';
import fieldStyles from '../../components/Field.module.css';
import styles from './FirewallPage.module.css';

const SETTINGS = ['dropInvalid', 'mssClamp', 'synFloodProtection', 'pingLimit'] as const;

export interface ProtectionCardProps {
  settings: FirewallSettings;
  onChange: (settings: FirewallSettings) => void;
}

/** The global protections of SPEC §16.1a as switches with a one-line explanation each. */
export function ProtectionCard({ settings, onChange }: ProtectionCardProps) {
  const { t } = useTranslation();
  const id = useId();
  return (
    <Card title={t('firewall.protection.title')}>
      <ul className={styles.switches}>
        {SETTINGS.map((setting) => (
          <li key={setting} className={styles.checkboxField}>
            <label className={styles.choice}>
              <input
                type="checkbox"
                role="switch"
                checked={settings[setting]}
                aria-describedby={`${id}-${setting}`}
                onChange={(event) =>
                  onChange({ ...settings, [setting]: event.currentTarget.checked })
                }
              />
              {t(`firewall.protection.${setting}`)}
            </label>
            <p id={`${id}-${setting}`} className={fieldStyles.hint}>
              {t(`firewall.protection.${setting}Hint`)}
            </p>
          </li>
        ))}
      </ul>
    </Card>
  );
}
