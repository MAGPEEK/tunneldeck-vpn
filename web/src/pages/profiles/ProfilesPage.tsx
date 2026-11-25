import { useMutation, useQueryClient } from '@tanstack/react-query';
import { FileUp, Plus } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { deleteProfile } from '../../api/profiles';
import { queryKeys } from '../../api/queryKeys';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Notice } from '../../components/Notice';
import { Page } from '../../layout/Page';
import { useConnection, useProfiles } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import { ImportPanel } from './ImportPanel';
import { ProfileTable } from './ProfileTable';
import type { ProfileFormState } from './profileFormState';

export function ProfilesPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const profiles = useProfiles();
  const connection = useConnection();
  const [importing, setImporting] = useState(false);
  const remove = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => client.invalidateQueries({ queryKey: queryKeys.profiles }),
  });

  const open = (path: string, state?: ProfileFormState) => void navigate(path, { state });

  return (
    <Page
      title={t('pages.profiles.title')}
      actions={
        <>
          <Button
            icon={<FileUp size={16} aria-hidden="true" />}
            aria-expanded={importing}
            onClick={() => setImporting((value) => !value)}
          >
            {t('profiles.import')}
          </Button>
          <Button
            variant="primary"
            icon={<Plus size={16} aria-hidden="true" />}
            onClick={() => open('/profiles/new')}
          >
            {t('profiles.new')}
          </Button>
        </>
      }
    >
      {importing && <ImportPanel onCancel={() => setImporting(false)} />}
      {profiles.isError && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, profiles.error)}
        </Notice>
      )}
      {remove.isError && (
        <Notice tone="danger" role="alert">
          {t('profiles.deleteFailed')}
        </Notice>
      )}
      <Card>
        <ProfileTable
          profiles={profiles.data ?? []}
          loading={profiles.isPending}
          status={connection.data}
          deletingId={remove.isPending ? remove.variables : undefined}
          onEdit={(profile) => open(`/profiles/${profile.id}`)}
          onDuplicate={(profile) => open('/profiles/new', { duplicateOf: profile.id })}
          onDelete={(profile) => remove.mutate(profile.id)}
        />
      </Card>
    </Page>
  );
}
