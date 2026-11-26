import { Globe, MonitorSmartphone, ShieldCheck, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { ConnectionStatus } from '../../api/connection';
import type { FirewallState } from '../../api/firewall';
import type { StateTone } from '../../components/StatePill';
import { formatBitRate } from '../../format/format';
import { useMediaQuery } from '../../hooks/useMediaQuery';
import { ConnectedSince } from './ConnectedSince';
import styles from './ConnectionLine.module.css';
import {
  NARROW_QUERY,
  STATE_TONES,
  activeForwards,
  activeRules,
  firewallLine,
  lineLayout,
  tunnelLine,
  tunnelUp,
  type LineStyle,
} from './overview';

export interface ConnectionLineProps {
  status: ConnectionStatus;
  /** Host name or address of the VPN server; "" when unknown. */
  serverHost: string;
  protocolLabel: string;
  firewall: FirewallState | undefined;
  /** Devices seen on the local LAN; undefined while unknown. */
  deviceCount: number | undefined;
  version: string | undefined;
}

/** VPN server, this device and the local LAN in one row, joined by state-coloured links. */
export function ConnectionLine(props: ConnectionLineProps) {
  const { status, serverHost, protocolLabel, firewall, deviceCount, version } = props;
  const { t, i18n } = useTranslation();
  const locale = i18n.resolvedLanguage ?? 'en';
  const layout = lineLayout(useMediaQuery(NARROW_QUERY));
  const live = tunnelUp(status.state);
  const rate = (bytesPerSecond: number) => (live ? formatBitRate(bytesPerSecond, locale) : '–');
  const rules = firewall ? activeRules(firewall) : 0;
  const forwards = firewall ? activeForwards(firewall) : 0;
  const lan = lanText(t, firewall, deviceCount);
  const summary = t('dashboard.line.summary', {
    state: t(`connection.state.${status.state}`),
    host: serverHost || '–',
    rules: t('dashboard.line.rules', { count: rules }),
    forwards: t('dashboard.line.forwards', { count: forwards }),
    lan: lan || '–',
  });

  return (
    <div className={styles.overview}>
      <div
        role="group"
        aria-label={summary}
        data-layout={layout}
        className={`${styles.line} ${layout === 'vertical' ? styles.vertical : ''}`}
      >
        <Node icon={Globe} title={serverHost || t('dashboard.line.vpn')} sub={protocolLabel} />
        <LineLink
          style={tunnelLine(status.state)}
          kind="tunnel"
          above={t('dashboard.line.received', { rate: rate(status.rateIn) })}
          below={t('dashboard.line.sent', { rate: rate(status.rateOut) })}
        />
        <Node
          icon={ShieldCheck}
          accent
          title={t('dashboard.line.device')}
          sub={<DeviceState status={status} />}
          subTone={STATE_TONES[status.state]}
        />
        <LineLink
          style={firewallLine(firewall, status)}
          kind="firewall"
          above={t('dashboard.line.rules', { count: rules })}
          below={t('dashboard.line.forwards', { count: forwards })}
        />
        <Node icon={MonitorSmartphone} title={t('dashboard.line.lan')} sub={lan || '–'} />
      </div>
      <div className={styles.footer}>
        <span>
          {t('dashboard.line.vpnIp')}{' '}
          <span className={styles.mono}>{(live && status.vpnIp) || '–'}</span>
        </span>
        <span className={styles.center}>
          {[firewall?.hostAddress, version && t('dashboard.line.version', { version })]
            .filter(Boolean)
            .join(' · ')}
        </span>
        <span className={styles.links}>
          <Link to="/log">{t('dashboard.line.showLog')}</Link>
          <Link to="/firewall">{t('dashboard.line.openFirewall')}</Link>
        </span>
      </div>
    </div>
  );
}

function lanText(
  t: ReturnType<typeof useTranslation>['t'],
  firewall: FirewallState | undefined,
  deviceCount: number | undefined,
): string {
  const subnet = firewall?.lanSubnets[0];
  const devices =
    deviceCount === undefined ? undefined : t('dashboard.line.devices', { count: deviceCount });
  return [subnet, devices].filter(Boolean).join(' · ');
}

function DeviceState({ status }: { status: ConnectionStatus }) {
  const { t } = useTranslation();
  if (status.state !== 'connected') {
    return <>{t(`connection.state.${status.state}`)}</>;
  }
  return (
    <>
      {t('dashboard.line.connectedFor')} <ConnectedSince since={status.since} />
    </>
  );
}

interface NodeProps {
  icon: LucideIcon;
  title: string;
  sub: ReactNode;
  subTone?: StateTone;
  accent?: boolean;
}

function Node({ icon: Icon, title, sub, subTone, accent = false }: NodeProps) {
  return (
    <div className={styles.node}>
      <span className={`${styles.icon} ${accent ? styles.accent : ''}`}>
        <Icon size={22} aria-hidden="true" />
      </span>
      <span className={styles.title}>{title}</span>
      <span className={`${styles.sub} ${subTone ? styles[`text-${subTone}`] : ''}`}>{sub}</span>
    </div>
  );
}

interface LinkProps {
  style: LineStyle;
  kind: 'tunnel' | 'firewall';
  above: string;
  below: string;
}

/** A link between two nodes with its labels above and below. */
function LineLink({ style, kind, above, below }: LinkProps) {
  return (
    <div className={styles.link}>
      <span className={styles.linkText}>{above}</span>
      <span
        className={`${styles.bar} ${style.dashed ? styles.dashed : styles[style.tone]}`}
        data-link={kind}
        data-tone={style.tone}
        data-dashed={style.dashed}
        aria-hidden="true"
      />
      <span className={styles.linkText}>{below}</span>
    </div>
  );
}
