import { TriangleAlert } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { ConnectionStatus } from '../../api/connection';
import type { FirewallState } from '../../api/firewall';
import type { Profile } from '../../api/profiles';
import { AdvisoryList } from '../../advisories/AdvisoryList';
import { Button } from '../../components/Button';
import { translateDynamic } from '../../i18n/dynamic';
import { protocolName } from '../profiles/profileText';
import styles from './ConnectionCard.module.css';
import { ConnectionLine } from './ConnectionLine';

export type ConnectionAction = 'connect' | 'disconnect' | 'reconnect';

export interface ConnectionCardProps {
  status: ConnectionStatus;
  profiles: Profile[];
  pending?: ConnectionAction;
  actionError?: string;
  onConnect: (profileId: string) => void;
  onDisconnect: () => void;
  onReconnect: () => void;
  firewall?: FirewallState;
  /** Devices seen on the local LAN; undefined while unknown. */
  deviceCount?: number;
  version?: string;
  /** Whether the connection line is shown; true unless the user hid it. */
  showLine?: boolean;
  /**
   * Renders what follows the card (the connection details) with the
   * Connect, Reconnect and Disconnect buttons as its footer. Without it the
   * buttons sit at the end of the card.
   */
  details?: (actions: ReactNode) => ReactNode;
}

/** The server's host name without port: from the profile, else from the live remote. */
function serverHost(profile: Profile | undefined, remote: string | undefined): string {
  const host = profile?.settings.remoteHost;
  if (typeof host === 'string' && host !== '') {
    return host;
  }
  return remote?.replace(/:d+$/, '') ?? '';
}

function initialProfileId(status: ConnectionStatus, profiles: Profile[]): string {
  const current = profiles.find((profile) => profile.id === status.profileId);
  return (current ?? profiles[0])?.id ?? '';
}

export function ConnectionCard(props: ConnectionCardProps) {
  const { status, profiles, actionError } = props;
  const { t } = useTranslation();
  const [selectedId, setSelectedId] = useState(() => initialProfileId(status, profiles));
  const idle = status.state === 'disconnected' || status.state === 'error';
  const shownId = idle ? selectedId : (status.profileId ?? selectedId);
  const profile = profiles.find((candidate) => candidate.id === shownId);
  const protocol = protocolName(t, status.protocol ?? profile?.protocol ?? 'openvpn');
  const advisories = idle ? (profile?.advisories ?? []) : status.advisories;

  const actions = (
    <div className={styles.actions}>
      <Actions {...props} selectedId={selectedId} onSelect={setSelectedId} />
    </div>
  );
  return (
    <>
      <section className={styles.card} aria-label={t('connection.label')}>
        <span className="visually-hidden" aria-live="polite" aria-atomic="true">
          {t(`connection.state.${status.state}`)}
        </span>
        {status.state === 'error' && <ErrorLine status={status} />}
        {status.routingWarning !== undefined && status.state !== 'error' && <RoutingWarning />}
        {actionError !== undefined && (
          <p role="alert" className={styles.error}>
            {actionError}
          </p>
        )}
        {props.showLine !== false && (
          <ConnectionLine
            status={status}
            serverHost={serverHost(profile, status.remote)}
            protocolLabel={protocol}
            firewall={props.firewall}
            deviceCount={props.deviceCount}
            version={props.version}
          />
        )}
        {!props.details && actions}
        <AdvisoryList advisories={advisories} />
      </section>
      {props.details?.(actions)}
    </>
  );
}

function ErrorLine({ status }: { status: ConnectionStatus }) {
  const { t } = useTranslation();
  const code = status.lastError?.code;
  const message = status.lastError?.message || status.message;
  const reason = code ? translateDynamic(t, `connection.errorCode.${code}`, '') : '';
  const text = [reason, message].filter(Boolean).join(' – ');
  return (
    <p className={styles.error}>
      {text || t('connection.errorUnknown')} <Link to="/log">{t('connection.openLog')}</Link>
    </p>
  );
}

/** The tunnel is up, but the routing of forwarded traffic failed; the server retries it. */
function RoutingWarning() {
  const { t } = useTranslation();
  return (
    <p role="status" className={styles.warning}>
      <TriangleAlert size={16} className={styles.warningIcon} aria-hidden="true" />
      <span>
        {t('connection.routingWarning')} <Link to="/log">{t('connection.openLog')}</Link>
      </span>
    </p>
  );
}

interface ActionsProps extends ConnectionCardProps {
  selectedId: string;
  onSelect: (id: string) => void;
}

function Actions({
  status,
  profiles,
  pending,
  selectedId,
  onSelect,
  onConnect,
  onDisconnect,
  onReconnect,
}: ActionsProps) {
  const { t } = useTranslation();
  switch (status.state) {
    case 'disconnected':
    case 'error':
      return (
        <>
          {profiles.length > 1 && (
            <select
              className={styles.select}
              aria-label={t('connection.profile')}
              value={selectedId}
              onChange={(event) => onSelect(event.currentTarget.value)}
            >
              {profiles.map((profile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.name}
                </option>
              ))}
            </select>
          )}
          <Button
            variant="primary"
            loading={pending === 'connect'}
            disabled={selectedId === ''}
            onClick={() => onConnect(selectedId)}
          >
            {status.state === 'error' ? t('connection.tryAgain') : t('connection.connect')}
          </Button>
        </>
      );
    case 'connected':
    case 'reconnecting':
      return (
        <>
          <Button
            loading={pending === 'reconnect'}
            disabled={pending !== undefined}
            onClick={onReconnect}
          >
            {t('connection.reconnect')}
          </Button>
          <Button
            loading={pending === 'disconnect'}
            disabled={pending !== undefined}
            onClick={onDisconnect}
          >
            {t('connection.disconnect')}
          </Button>
        </>
      );
    case 'connecting':
    case 'disconnecting':
      return (
        <Button
          loading={status.state === 'disconnecting' || pending === 'disconnect'}
          onClick={onDisconnect}
        >
          {t('connection.disconnect')}
        </Button>
      );
  }
}
