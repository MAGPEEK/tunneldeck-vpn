import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ClipboardPaste, Plus } from 'lucide-react';
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
import { HelpLink } from '../help/HelpLink';
import { ImportFailureNotice } from './import/ImportFailureNotice';
import { LoadProfileFileButton } from './import/LoadProfileFileButton';
import { ProfileDropZone } from './import/ProfileDropZone';
import { useProfileImport } from './import/useProfileImport';
import { ImportPanel } from './ImportPanel';
import { ProfileTable } from './ProfileTable';
import type { ProfileFormState } from './profileFormState';

export function ProfilesPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const profiles = useProfiles();
  const connection = useConnection();
  const profileImport = useProfileImport();
  const [pasting, setPasting] = useState(false);
  const remove = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => client.invalidateQueries({ queryKey: queryKeys.profiles }),
  });

  const open = (path: string, state?: ProfileFormState) => void navigate(path, { state });
  const loadFile = (file: File) => void profileImport.loadFile(file);
  const failure = profileImport.failure;
  const fileFailure = failure?.fileName !== undefined ? failure : undefined;

  return (
    <ProfileDropZone onFile={loadFile}>
      <Page
        title={t('pages.profiles.title')}
        actions={
          <>
            <LoadProfileFileButton loading={profileImport.pending} onFile={loadFile} />
            <Button
              icon={<ClipboardPaste size={16} aria-hidden="true" />}
              aria-expanded={pasting}
              onClick={() => setPasting((value) => !value)}
            >
              {t('profiles.pasteConfig')}
            </Button>
            <Button
              icon={<Plus size={16} aria-hidden="true" />}
              onClick={() => open('/profiles/new')}
            >
              {t('profiles.new')}
            </Button>
            <HelpLink section="profiles" />
          </>
        }
      >
        {fileFailure && <ImportFailureNotice failure={fileFailure} />}
        {pasting && (
          <ImportPanel
            pending={profileImport.pending}
            failure={fileFailure ? undefined : failure}
            onSubmit={profileImport.loadText}
            onCancel={() => setPasting(false)}
          />
        )}
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
    </ProfileDropZone>
  );
}
