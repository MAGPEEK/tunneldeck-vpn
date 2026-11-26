import { Copy, Pencil, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ConnectionStatus } from '../../api/connection';
import type { Profile } from '../../api/profiles';
import { Button } from '../../components/Button';
import { StatePill } from '../../components/StatePill';
import { Table, type Column } from '../../components/Table';
import { profileServer, protocolShortName } from './profileText';
import styles from './ProfileTable.module.css';

export interface ProfileTableProps {
  profiles: Profile[];
  loading: boolean;
  status: ConnectionStatus | undefined;
  deletingId: string | undefined;
  onEdit: (profile: Profile) => void;
  onDuplicate: (profile: Profile) => void;
  onDelete: (profile: Profile) => void;
}

export function ProfileTable(props: ProfileTableProps) {
  const { profiles, loading, status, deletingId, onEdit, onDuplicate, onDelete } = props;
  const { t } = useTranslation();
  const [confirmingId, setConfirmingId] = useState<string>();
  const activeId = status?.state === 'disconnected' ? undefined : status?.profileId;

  const columns: Column<Profile>[] = [
    { key: 'name', header: t('profiles.column.name'), render: (profile) => profile.name },
    {
      key: 'protocol',
      header: t('profiles.column.protocol'),
      render: (profile) => protocolShortName(t, profile.protocol),
    },
    {
      key: 'server',
      header: t('profiles.column.server'),
      render: (profile) => <span className={styles.mono}>{profileServer(profile) || '–'}</span>,
    },
    {
      key: 'daily',
      header: t('profiles.column.dailyReconnect'),
      render: (profile) =>
        profile.dailyReconnect.enabled ? profile.dailyReconnect.time : t('profiles.off'),
    },
    {
      key: 'status',
      header: t('profiles.column.status'),
      render: (profile) =>
        profile.id === activeId ? (
          <StatePill tone="success">{t('profiles.active')}</StatePill>
        ) : null,
    },
    {
      key: 'actions',
      header: <span className="visually-hidden">{t('profiles.column.actions')}</span>,
      align: 'end',
      render: (profile) => {
        return (
          <div className={styles.actions}>
            <Button
              variant="secondary"
              size="small"
              icon={<Pencil size={16} aria-hidden="true" />}
              onClick={() => onEdit(profile)}
              aria-label={t('profiles.editNamed', { name: profile.name })}
            >
              {t('profiles.edit')}
            </Button>
            <Button
              variant="secondary"
              size="small"
              icon={<Copy size={16} aria-hidden="true" />}
              onClick={() => onDuplicate(profile)}
              aria-label={t('profiles.duplicateNamed', { name: profile.name })}
            >
              {t('profiles.duplicate')}
            </Button>
            <Button
              variant="danger"
              size="small"
              icon={<Trash2 size={16} aria-hidden="true" />}
              aria-label={t('profiles.deleteNamed', { name: profile.name })}
              onClick={() => setConfirmingId(profile.id)}
            >
              {t('profiles.delete')}
            </Button>
          </div>
        );
      },
    },
  ];

  const confirmRow = (profile: Profile) => {
    if (profile.id !== confirmingId) return undefined;
    const inUse = profile.id === activeId;
    return (
      <div className={styles.confirm} role="group" aria-label={t('profiles.confirmLabel')}>
        <span>
          {inUse
            ? t('profiles.confirmDeleteInUse')
            : t('profiles.confirmDelete', { name: profile.name })}
        </span>
        <div className={styles.actions}>
          <Button onClick={() => setConfirmingId(undefined)}>{t('profiles.cancel')}</Button>
          <Button
            variant="danger"
            loading={deletingId === profile.id}
            onClick={() => onDelete(profile)}
          >
            {inUse ? t('profiles.confirmDeleteInUseButton') : t('profiles.confirmDeleteButton')}
          </Button>
        </div>
      </div>
    );
  };

  return (
    <Table
      columns={columns}
      rows={profiles}
      rowKey={(profile) => profile.id}
      rowDetail={confirmRow}
      caption={t('pages.profiles.title')}
      emptyMessage={loading ? t('session.loading') : t('profiles.empty')}
    />
  );
}
