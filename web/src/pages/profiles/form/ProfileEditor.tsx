import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  useEffect,
  useRef,
  useState,
  type Dispatch,
  type FormEvent,
  type ReactNode,
  type SetStateAction,
} from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { isApiError } from '../../../api/client';
import { localizedFieldErrors } from '../../../api/fieldErrors';
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
import { useDriverText } from '../../../i18n/dynamic';
import type { ProfileFormState } from '../profileFormState';
import { SchemaForm } from '../schema/SchemaForm';
import {
  isVisible,
  schemaFields,
  toRequestPart,
  type FormValues,
  type SecretState,
  type SecretStates,
} from '../schema/schemaValues';
import { KeyPairPanel } from './KeyPairPanel';
import { splitProfileErrors } from './formErrors';
import { ImportWarnings } from './ImportWarnings';
import { stillMissing } from './importMissing';
import styles from './ProfileForm.module.css';
import { ProtocolChooser } from './ProtocolChooser';
import { ReconnectNotice } from './ReconnectNotice';
import { AccessSection } from './AccessSection';
import { ScheduleSection } from './ScheduleSection';

/** The private-key secret of each protocol that can generate a key pair. */
const KEY_PAIR_FIELDS: Readonly<Record<string, string>> = { wireguard: 'privateKey' };

export interface ProfileDraft {
  name: string;
  protocol: string;
  values: FormValues;
  secrets: SecretStates;
  dailyReconnect: DailyReconnect;
  publicAddress: string;
}

export interface ProfileEditorProps {
  /** The saved profile when editing; undefined when creating. */
  profile: Profile | undefined;
  initial: ProfileDraft;
  drivers: Driver[];
  timeZone: string | undefined;
  importWarnings?: ImportWarning[];
  /** Keys the import left empty; highlighted until filled in. */
  importMissing?: string[];
  notice?: string;
  justSaved?: boolean;
  /** Fresh form state for another protocol (create only). */
  draftFor: (protocol: string) => ProfileDraft;
}

export function ProfileEditor(props: ProfileEditorProps) {
  const {
    profile,
    initial,
    drivers,
    timeZone,
    importWarnings,
    importMissing,
    notice,
    justSaved,
    draftFor,
  } = props;
  const { t } = useTranslation();
  const text = useDriverText();
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
      publicAddress: draft.publicAddress.trim(),
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
      ? splitProfileErrors(localizedFieldErrors(t, save.error), visibleKeys)
      : undefined;
  const missingFields = schema
    ? stillMissing(schema, importMissing ?? [], draft.values, draft.secrets)
    : [];
  const schemaErrors = {
    ...Object.fromEntries(
      missingFields.map((field) => [field.key, t('profileForm.missingFromFile')]),
    ),
    ...fieldErrors?.schema,
  };

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
      {missingFields.length > 0 && (
        <Notice tone="warning" title={t('profileForm.missingTitle')}>
          <ul className={styles.warningList}>
            {missingFields.map((field) => (
              <li key={field.key}>{text(field.labelKey)}</li>
            ))}
          </ul>
        </Notice>
      )}
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
          errors={schemaErrors}
          onValuesChange={(values) => setDraft({ ...draft, values })}
          onSecretsChange={(secrets) => setDraft({ ...draft, secrets })}
          fieldAddons={keyPairAddon(draft, profile, setDraft)}
        />
      )}
      <ScheduleSection
        value={draft.dailyReconnect}
        timeZone={timeZone}
        error={fieldErrors?.dailyReconnectTime}
        onChange={(dailyReconnect) => setDraft({ ...draft, dailyReconnect })}
      />
      <AccessSection
        publicAddress={draft.publicAddress}
        error={fieldErrors?.publicAddress}
        onChange={(publicAddress) => setDraft({ ...draft, publicAddress })}
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

/** The key pair generator below the private key, for protocols that have one. */
function keyPairAddon(
  draft: ProfileDraft,
  profile: Profile | undefined,
  setDraft: Dispatch<SetStateAction<ProfileDraft>>,
): Record<string, ReactNode> | undefined {
  const key = KEY_PAIR_FIELDS[draft.protocol];
  if (key === undefined) {
    return undefined;
  }
  const takeGenerated = (privateKey: string) =>
    setDraft((current) => ({
      ...current,
      secrets: { ...current.secrets, [key]: typedSecret(current.secrets[key], privateKey) },
    }));
  return {
    [key]: (
      <KeyPairPanel
        protocol={draft.protocol}
        state={draft.secrets[key]}
        storedPublicKey={profile?.derived?.publicKey}
        onGenerated={takeGenerated}
      />
    ),
  };
}

/** A value for a secret as if typed in: it replaces a saved one, else it is new. */
function typedSecret(current: SecretState | undefined, value: string): SecretState {
  return current === undefined || current.mode === 'new'
    ? { mode: 'new', value }
    : { mode: 'replace', value };
}

/** After an update every secret the server now holds reads "Stored" again. */
function storedSecrets(current: SecretStates, saved: Profile): SecretStates {
  const next: SecretStates = {};
  for (const key of Object.keys(current)) {
    next[key] = saved.secrets[key]?.hasValue ? { mode: 'stored' } : { mode: 'new', value: '' };
  }
  return next;
}
