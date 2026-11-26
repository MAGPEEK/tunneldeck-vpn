import { useTranslation } from 'react-i18next';
import type { LanDevice } from '../../api/firewall';
import { Button } from '../../components/Button';
import { Field } from '../../components/Field';
import styles from './FirewallPage.module.css';

export interface DevicePickerProps {
  label: string;
  value: string;
  onChange: (address: string) => void;
  /** The host's LAN neighbours; `undefined` while loading or when unavailable. */
  devices: readonly LanDevice[] | undefined;
  devicesFailed: boolean;
  /** Offered as "This device's address"; empty for none. */
  hostAddress: string;
  hostAddresses: readonly string[];
  /** Offered as "Whole local LAN (…)", one button per subnet; omitted for single addresses. */
  lanSubnets?: readonly string[];
  placeholder: string;
  hint?: string;
  error?: string;
}

/**
 * Step 1 of the editor: pick a LAN neighbour (name, IP, MAC), take this
 * device's own address or a whole LAN subnet, or type any address.
 */
export function DevicePicker(props: DevicePickerProps) {
  const { value, onChange, devices, hostAddress, hostAddresses } = props;
  const { t } = useTranslation();
  const chosen = value.trim();
  const neighbours = (devices ?? []).filter(
    (device) => device.onLan && !hostAddresses.includes(device.address),
  );
  const reserveHint = chosen !== '' && !hostAddresses.includes(chosen) && !chosen.includes('/');
  return (
    <div className={styles.picker}>
      {neighbours.length > 0 && (
        <ul className={styles.deviceList} aria-label={t('firewall.device.listLabel')}>
          {neighbours.map((device) => (
            <li key={device.address}>
              <button
                type="button"
                className={styles.device}
                aria-pressed={chosen === device.address}
                onClick={() => onChange(device.address)}
              >
                <span className={styles.deviceName}>
                  {device.name || t('firewall.device.unnamed')}
                </span>
                <span className={styles.mono}>{device.address}</span>
                <span className={styles.deviceMac}>{device.mac}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {devices !== undefined && !props.devicesFailed && neighbours.length === 0 && (
        <p className={styles.secondary}>{t('firewall.device.none')}</p>
      )}
      {props.devicesFailed && <p className={styles.secondary}>{t('firewall.device.failed')}</p>}
      {hostAddress !== '' && chosen !== hostAddress && (
        <Button variant="ghost" onClick={() => onChange(hostAddress)}>
          {t('firewall.device.useHost', { address: hostAddress })}
        </Button>
      )}
      {(props.lanSubnets ?? [])
        .filter((subnet) => subnet !== chosen)
        .map((subnet) => (
          <Button key={subnet} variant="ghost" onClick={() => onChange(subnet)}>
            {t('firewall.device.useLan', { subnet })}
          </Button>
        ))}
      <Field
        label={props.label}
        hint={
          [props.hint, reserveHint ? t('firewall.device.reserveHint') : '']
            .filter(Boolean)
            .join(' ') || undefined
        }
        placeholder={props.placeholder}
        className={styles.monoField}
        value={value}
        spellCheck={false}
        error={props.error}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
    </div>
  );
}
