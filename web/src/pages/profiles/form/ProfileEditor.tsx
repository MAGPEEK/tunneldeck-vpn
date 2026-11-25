import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { isApiError } from '../../../api/client';
import {
  createProfile,
  updateProfile,
  type DailyReconnect,
  type Driver,
  type ImportWarning,
  type Profile,
  type ProfileRequest,
} from '../../../api/profiles';
import { queryKeys } from '../../../api/queryKeys';
import { AdvisoryNotice } from '../../../advisories/AdvisoryList';
import { Button } from '../../../components/Button';
import { Card } from '../../../components/Card';
import { Field } from '../../../components/Field';
import { Notice } from '../../../components/Notice';
import { genericErrorMessage } from '../../auth/formError';
import type { ProfileFormState } from '../profileFormState';
import { SchemaForm } from '../schema/SchemaForm';
import {
  isVisible,
  schemaFields,
  toRequestPart,
  type FormValues,
  type SecretStates,
} from '../schema/schemaValues';
import { splitProfileErrors } from './formErrors';
import { ImportWarnings } from './ImportWarnings';
import styles from './ProfileForm.module.css';
import { ProtocolChooser } from './ProtocolChooser';
import { ReconnectNotice } from './ReconnectNotice';
import { ScheduleSection } from './ScheduleSection';

export interface ProfileDraft {
  name: string;
  protocol: string;
  values: FormValues;
  secrets: SecretStates;
  dailyReconnect: DailyReconnect;
}

export interface ProfileEditorProps {
  /** The saved profile when editing; undefined when creating. */
  profile: Profile | undefined;
  initial: ProfileDraft;
  drivers: Driver[];
  timeZone: string | undefined;
  importWarnings?: ImportWarning[];
  notice?: string;
  justSaved?: boolean;
  /** Fresh form state for another protocol (create only). */
  draftFor: (protocol: string) => ProfileDraft;
}

export function ProfileEditor(props: ProfileEditorProps) {
  const { profile, initial, drivers, timeZone, importWarnings, notice, justSaved, draftFor } =
    props;
  const { t } = useTranslation();
  const navigate = useNavigate();
  const client = useQueryClient();
  const [draft, setDraft] = useState(initial);
  const [saved, setSaved] = useState(justSaved === true);
  const formRef = useRef<HTMLFormElement>(null);
  const schema = drivers.find((driver) => driver.protocol === draft.protocol)?.schema;

  const save = useMutation({
    mutationFn: (body: ProfileRequest) =>
      profile ? updateProfile(profile.id, body) : createProfile(body),
    onSuccess: (result) => {
      client.setQueryData(queryKeys.profile(result.id), result);
      void client.invalidateQueries({ queryKey: queryKeys.profiles, exact: true });
      if (profile) {
        setSaved(true);
        setDraft((current) => ({ ...current, secrets: storedSecrets(current.secrets, result) }));
        return;
      }
      client.removeQueries({ queryKey: queryKeys.importDraft });
      const state: ProfileFormState = { saved: true };
      void navigate(`/profiles/${result.id}`, { replace: true, state });
    },
  });

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!schema) return;
    setSaved(false);
    save.mutate({
      name: draft.name.trim(),
      protocol: draft.protocol,
      dailyReconnect: draft.dailyReconnect,
      ...toRequestPart(schema, draft.values, draft.secrets),
    });
  };

  // The save result is shown above the form; bring it into view.
  const failed = save.isError;
  useEffect(() => {
    if (saved || failed) {
      formRef.current?.scrollIntoView?.({ block: 'start' });
    }
  }, [saved, failed]);

  const visibleKeys = schema
    ? schemaFields(schema)
        .filter((field) => isVisible(field, draft.values, draft.secrets))
        .map((field) => field.key)
    : [];
  const fieldErrors =
    isApiError(save.error) && save.error.code === 'validation_failed'
      ? splitProfileErrors(save.error.fields, visibleKeys)
      : undefined;

  return (
    <form ref={formRef} className={styles.form} onSubmit={submit}>
      {saved && (
        <Notice tone="info" role="status" title={t('profileForm.saved')}>
          {profile && <ReconnectNotice profileId={profile.id} />}
        </Notice>
      )}
      {profile && <AdvisoryNotice advisories={profile.advisories} />}
      {notice && <Notice tone="info">{notice}</Notice>}
      {importWarnings && importWarnings.length > 0 && <ImportWarnings warnings={importWarnings} />}
      {save.isError && (
        <Notice
          tone="danger"
          role="alert"
          title={fieldErrors ? t('profileForm.invalid') : undefined}
        >
          {fieldErrors
            ? fieldErrors.other.map((message) => <p key={message}>{message}</p>)
            : genericErrorMessage(t, save.error)}
        </Notice>
      )}
      <Card>
        <div className={styles.fields}>
          <Field
            label={t('profileForm.name')}
            value={draft.name}
            required
            maxLength={64}
            autoComplete="off"
            error={fieldErrors?.name}
            onChange={(event) => setDraft({ ...draft, name: event.currentTarget.value })}
          />
          {!profile && (
            <ProtocolChooser
              available={drivers.map((driver) => driver.protocol)}
              value={draft.protocol}
              onChange={(protocol) => setDraft({ ...draftFor(protocol), name: draft.name })}
            />
          )}
        </div>
      </Card>
      {schema && (
        <SchemaForm
          schema={schema}
          values={draft.values}
          secrets={draft.secrets}
          errors={fieldErrors?.schema ?? {}}
          onValuesChange={(values) => setDraft({ ...draft, values })}
          onSecretsChange={(secrets) => setDraft({ ...draft, secrets })}
        />
      )}
      <ScheduleSection
        value={draft.dailyReconnect}
        timeZone={timeZone}
        error={fieldErrors?.dailyReconnectTime}
        onChange={(dailyReconnect) => setDraft({ ...draft, dailyReconnect })}
      />
      <div className={styles.buttons}>
        <Button type="submit" variant="primary" loading={save.isPending} disabled={!schema}>
          {t('profileForm.save')}
        </Button>
        <Button onClick={() => void navigate('/profiles')}>{t('profiles.cancel')}</Button>
      </div>
    </form>
  );
}

/** After an update every secret the server now holds reads "Stored" again. */
function storedSecrets(current: SecretStates, saved: Profile): SecretStates {
  const next: SecretStates = {};
  for (const key of Object.keys(current)) {
    next[key] = saved.secrets[key]?.hasValue ? { mode: 'stored' } : { mode: 'new', value: '' };
  }
  return next;
}
