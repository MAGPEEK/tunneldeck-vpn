import type { TFunction } from 'i18next';
import { X } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { ConnectionStatus } from '../../api/connection';
import type { FirewallState } from '../../api/firewall';
import type { RemoteAccess } from '../../api/remoteAccess';
import { Card } from '../../components/Card';
import type { StateTone } from '../../components/StatePill';
import { formatBitRate, formatBytes, formatDateTime, parseTime } from '../../format/format';
import { RemoteAccessAddress } from '../../remoteAccess/RemoteAccessAddress';
import { remoteAccessTarget } from '../../remoteAccess/remoteAccessUrl';
import { CustomizePanel, CustomizeToggle } from './CustomizePanel';
import type { DashboardItem, DashboardItems } from './dashboardItems';
import {
  STATE_TONES,
  activeForwards,
  activeRules,
  firewallLine,
  forwardingBlocked,
  protectionsDegraded,
  tunnelUp,
} from './overview';
import styles from './StatusList.module.css';

export interface StatusListProps {
  status: ConnectionStatus;
  /** "host:port" of the VPN server; "" when unknown. */
  server: string;
  firewall: FirewallState | undefined;
  deviceCount: number | undefined;
  /** null when this build has no remote access. */
  remoteAccess: RemoteAccess | null | undefined;
  /** Public address of the shown profile; "" or undefined when not set. */
  publicAddress?: string;
  /** Which rows (and the connection line) this browser shows. */
  items: DashboardItems;
}

interface Row {
  id: DashboardItem;
  label: string;
  tone: StateTone;
  values: ReactNode[];
}

interface RowContext extends StatusListProps {
  t: TFunction;
  locale: string;
}

/** "Connection details": one row per part of the connection with a status dot. */
export function StatusList(props: StatusListProps) {
  const { t, i18n } = useTranslation();
  const [customizing, setCustomizing] = useState(false);
  const panelId = useId();
  const { items } = props;
  const context: RowContext = { ...props, t, locale: i18n.resolvedLanguage ?? 'en' };
  const rows = [
    tunnelRow(context),
    addressRow(context),
    encryptionRow(context),
    lanRow(context),
    firewallRow(context),
    remoteAccessRow(context),
    trafficRow(context),
  ].filter((row): row is Row => row !== undefined && items.isVisible(row.id));

  return (
    <Card
      title={t('dashboard.details.title')}
      actions={<CustomizeToggle open={customizing} panelId={panelId} onToggle={setCustomizing} />}
    >
      {customizing && <CustomizePanel id={panelId} items={items} />}
      <dl className={styles.list}>
        {rows.map((row) => (
          <div key={row.id} className={styles.row} data-row={row.id} data-tone={row.tone}>
            <dt className={styles.label}>
              <span className={`${styles.dot} ${styles[row.tone]}`} aria-hidden="true" />
              {row.label}
              <span className="visually-hidden"> ({t(`dashboard.details.tone.${row.tone}`)})</span>
            </dt>
            <dd className={styles.values}>
              {row.values.map((value, index) => (
                <span key={index}>{value}</span>
              ))}
              <button
                type="button"
                className={styles.hide}
                aria-label={t('dashboard.customize.hide', { item: row.label })}
                onClick={() => items.setVisible(row.id, false)}
              >
                <X size={14} aria-hidden="true" />
              </button>
            </dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

function tunnelRow({ status, t, locale }: RowContext): Row {
  const live = tunnelUp(status.state);
  const rate = (value: number) => (live ? formatBitRate(value, locale) : '–');
  return {
    id: 'tunnel',
    label: t('dashboard.details.tunnel'),
    tone: STATE_TONES[status.state],
    values: [
      t(`connection.state.${status.state}`),
      t('dashboard.details.rateIn', { rate: rate(status.rateIn) }),
      t('dashboard.details.rateOut', { rate: rate(status.rateOut) }),
    ],
  };
}

function addressRow({ status, server, t, locale }: RowContext): Row {
  const live = tunnelUp(status.state);
  const since = status.state === 'connected' ? parseTime(status.since) : undefined;
  const vpnIp = live ? status.vpnIp : undefined;
  return {
    id: 'address',
    label: t('dashboard.details.address'),
    tone: vpnIp ? 'success' : 'neutral',
    values: [
      since
        ? t('dashboard.details.connectedSince', { time: formatDateTime(since, locale) })
        : t('dashboard.details.notConnected'),
      <span className={styles.mono}>{vpnIp || '–'}</span>,
      <span className={styles.mono}>{(live && status.remote) || server || '–'}</span>,
    ],
  };
}

function encryptionRow({ status, t }: RowContext): Row | undefined {
  const { dataCipher, controlChannel } = status;
  if (!dataCipher && !controlChannel) {
    return undefined;
  }
  const values: ReactNode[] = [];
  if (dataCipher) {
    values.push(
      dataCipher === 'none'
        ? t('dashboard.details.dataChannelNone')
        : t('dashboard.details.dataChannel', { cipher: dataCipher }),
    );
  }
  if (controlChannel) {
    values.push(t('dashboard.details.controlChannel', { value: controlChannel }));
  }
  return {
    id: 'encryption',
    label: t('dashboard.details.encryption'),
    tone: dataCipher === 'none' ? 'danger' : 'success',
    values,
  };
}

function lanRow({ firewall, deviceCount, t }: RowContext): Row {
  const addresses = firewall?.hostAddresses ?? [];
  const subnets = firewall?.lanSubnets ?? [];
  return {
    id: 'lan',
    label: t('dashboard.details.lan'),
    tone: addresses.length > 0 ? 'success' : 'neutral',
    values: [
      <span className={styles.mono}>{addresses.join(', ') || '–'}</span>,
      <span className={styles.mono}>{subnets.join(', ') || '–'}</span>,
      deviceCount === undefined ? '–' : t('dashboard.line.devices', { count: deviceCount }),
    ],
  };
}

function firewallRow({ firewall, status, t }: RowContext): Row {
  const tone = firewallLine(firewall, status).tone;
  if (firewall === undefined) {
    return { id: 'firewall', label: t('dashboard.details.firewall'), tone, values: ['–'] };
  }
  const values: ReactNode[] = [
    t('dashboard.details.rules', { count: activeRules(firewall) }),
    t('dashboard.line.forwards', { count: activeForwards(firewall) }),
    protectionsDegraded(firewall)
      ? t('dashboard.details.protectionsLimited')
      : t('dashboard.details.protectionsOk'),
  ];
  if (forwardingBlocked(firewall)) {
    values.push(t('dashboard.details.ipForwardOff'));
  }
  return { id: 'firewall', label: t('dashboard.details.firewall'), tone, values };
}

function remoteAccessRow({ remoteAccess, publicAddress, status, t }: RowContext): Row | undefined {
  if (!remoteAccess) {
    return undefined;
  }
  const label = t('dashboard.details.remoteAccess');
  if (!remoteAccess.enabled) {
    return { id: 'remote', label, tone: 'neutral', values: [t('dashboard.details.remoteOff')] };
  }
  const port = t('dashboard.details.remoteOn', { port: remoteAccess.port });
  if (!remoteAccess.listening) {
    const values: ReactNode[] = [port];
    if (remoteAccess.lastError) {
      values.push(t('remoteAccess.lastError', { error: remoteAccess.lastError }));
    }
    return { id: 'remote', label, tone: 'warning', values };
  }
  const vpnIp = tunnelUp(status.state) ? status.vpnIp : undefined;
  const target = remoteAccessTarget(remoteAccess.port, publicAddress, vpnIp);
  return {
    id: 'remote',
    label,
    tone: 'success',
    values: [target ? <RemoteAccessAddress target={target} /> : port],
  };
}

function trafficRow({ status, t, locale }: RowContext): Row {
  const live = tunnelUp(status.state);
  const bytes = (value: number) => (live ? formatBytes(value, locale) : '–');
  return {
    id: 'traffic',
    label: t('dashboard.details.traffic'),
    tone: live ? 'success' : 'neutral',
    values: [
      t('dashboard.details.received', { bytes: bytes(status.bytesIn) }),
      t('dashboard.details.sent', { bytes: bytes(status.bytesOut) }),
    ],
  };
}
