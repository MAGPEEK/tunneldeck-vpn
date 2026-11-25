import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ConnectionState, ConnectionStatus } from '../../api/connection';
import type { Profile } from '../../api/profiles';
import { AdvisoryList } from '../../advisories/AdvisoryList';
import { Button } from '../../components/Button';
import { StatePill, type StateTone } from '../../components/StatePill';
import { translateDynamic } from '../../i18n/dynamic';
import { profileServer, protocolName } from '../profiles/profileText';
import { ConnectedSince } from './ConnectedSince';
import styles from './ConnectionCard.module.css';

const TONES: Record<ConnectionState, StateTone> = {
  disconnected: 'neutral',
  connecting: 'warning',
  reconnecting: 'warning',
  disconnecting: 'warning',
  connected: 'success',
  error: 'danger',
};

export type ConnectionAction = 'connect' | 'disconnect' | 'reconnect';

export interface ConnectionCardProps {
  status: ConnectionStatus;
  profiles: Profile[];
  pending?: ConnectionAction;
  actionError?: string;
  onConnect: (profileId: string) => void;
  onDisconnect: () => void;
  onReconnect: () => void;
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
  const name = idle ? profile?.name : (status.profileName ?? profile?.name);
  const tunnelUp = status.state === 'connected' || status.state === 'reconnecting';
  const server = (tunnelUp && status.remote) || (profile ? profileServer(profile) : '');
  const advisories = idle ? (profile?.advisories ?? []) : status.advisories;

  return (
    <section className={styles.card} aria-label={t('connection.label')}>
      <div className={styles.header}>
        <span aria-live="polite" aria-atomic="true">
          <StatePill tone={TONES[status.state]} dot>
            {t(`connection.state.${status.state}`)}
          </StatePill>
        </span>
        {name !== undefined && <h2 className={styles.name}>{name}</h2>}
        <StatePill>{protocolName(t, status.protocol ?? profile?.protocol ?? 'openvpn')}</StatePill>
        <div className={styles.actions}>
          <Actions {...props} selectedId={selectedId} onSelect={setSelectedId} />
        </div>
      </div>
      {status.state === 'error' && <ErrorLine status={status} />}
      {actionError !== undefined && (
        <p role="alert" className={styles.error}>
          {actionError}
        </p>
      )}
      <dl className={styles.values}>
        <div>
          <dt>{t('connection.server')}</dt>
          <dd className={styles.mono}>{server || '–'}</dd>
        </div>
        <div>
          <dt>{t('connection.vpnAddress')}</dt>
          <dd className={styles.mono}>{(tunnelUp && status.vpnIp) || '–'}</dd>
        </div>
        <div>
          <dt>{t('connection.since')}</dt>
          <dd>{status.state === 'connected' ? <ConnectedSince since={status.since} /> : '–'}</dd>
        </div>
      </dl>
      <AdvisoryList advisories={advisories} />
    </section>
  );
}

function ErrorLine({ status }: { status: ConnectionStatus }) {
  const { t } = useTranslation();
  const code = status.lastError?.code;
  const message = status.lastError?.message || status.message;
  const reason = code ? translateDynamic(t, `connection.errorCode.${code}`, '') : '';
  const text = [reason, message].filter(Boolean).join(' – ');
  return <p className={styles.error}>{text || t('connection.errorUnknown')}</p>;
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
