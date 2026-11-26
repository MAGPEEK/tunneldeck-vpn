import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import type { FirewallSettings, ProtectionLevel, ProtectionSupport } from '../../api/firewall';
import { Card } from '../../components/Card';
import fieldStyles from '../../components/Field.module.css';
import styles from './FirewallPage.module.css';

const SETTINGS = ['dropInvalid', 'mssClamp', 'synFloodProtection', 'pingLimit'] as const;

type Setting = (typeof SETTINGS)[number];

/** The support entry of each setting the host's kernel may lack; dropInvalid always works. */
const SUPPORT: Partial<Record<Setting, keyof Omit<ProtectionSupport, 'ruleCounters'>>> = {
  mssClamp: 'mssClamp',
  synFloodProtection: 'synFlood',
  pingLimit: 'ping',
};

/** The note key for a protection the kernel supports only partly or not at all. */
const NOTE = {
  full: undefined,
  global: 'firewall.protection.globalOnly',
  none: 'firewall.protection.notAvailable',
} as const satisfies Record<ProtectionLevel, string | undefined>;

export interface ProtectionCardProps {
  settings: FirewallSettings;
  /** What the host's kernel supports; without it no note is shown. */
  support?: ProtectionSupport;
  onChange: (settings: FirewallSettings) => void;
}

/**
 * The global protections of SPEC §16.1a as switches with a one-line explanation each,
 * plus a note when the host's kernel supports a protection only partly or not at all.
 */
export function ProtectionCard({ settings, support, onChange }: ProtectionCardProps) {
  const { t } = useTranslation();
  const id = useId();
  return (
    <Card title={t('firewall.protection.title')}>
      <ul className={styles.switches}>
        {SETTINGS.map((setting) => {
          const supportKey = SUPPORT[setting];
          const note = support && supportKey ? NOTE[support[supportKey]] : undefined;
          const describedBy = [`${id}-${setting}`, note && `${id}-${setting}-note`]
            .filter(Boolean)
            .join(' ');
          return (
            <li key={setting} className={styles.checkboxField}>
              <label className={styles.choice}>
                <input
                  type="checkbox"
                  role="switch"
                  checked={settings[setting]}
                  aria-describedby={describedBy}
                  onChange={(event) =>
                    onChange({ ...settings, [setting]: event.currentTarget.checked })
                  }
                />
                {t(`firewall.protection.${setting}`)}
              </label>
              <p id={`${id}-${setting}`} className={fieldStyles.hint}>
                {t(`firewall.protection.${setting}Hint`)}
              </p>
              {note && (
                <p id={`${id}-${setting}-note`} className={fieldStyles.hint}>
                  {t(note)}
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
