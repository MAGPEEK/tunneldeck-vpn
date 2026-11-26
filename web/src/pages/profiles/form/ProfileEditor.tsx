import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  useEffect,
  useRef,
  useState,
  type Dispatch,
  type FormEvent,
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
  type FormSchema,
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
import { schemaAddons, templateAddons } from './schemaAddons';
import { applyTemplate, changedTemplate, forceTemplate } from './templatePresets';
import { splitProfileErrors } from './formErrors';
import { ImportWarnings } from './ImportWarnings';
import { stillMissing } from './importMissing';
import styles from './ProfileForm.module.css';
import { ProtocolChooser } from './ProtocolChooser';
import { ReconnectNotice } from './ReconnectNotice';
import { AccessSection } from './AccessSection';
import { ScheduleSection } from './ScheduleSection';

export interface ProfileDraft {
  name: string;
  protocol: string;
  values: FormValues;
  secrets: SecretStates;
  dailyReconnect: DailyReconnect;
  publicAddress: string;
}

/** The draft and the fields the last template choice left as the user had changed them. */
interface EditorState {
  draft: ProfileDraft;
  templateKept: string[];
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
  const [editor, setEditor] = useState<EditorState>({ draft: initial, templateKept: [] });
  const [saved, setSaved] = useState(justSaved === true);
  const formRef = useRef<HTMLFormElement>(null);
  const { draft, templateKept } = editor;
  const schemaOf = (protocol: string) =>
    drivers.find((driver) => driver.protocol === protocol)?.schema;
  const schema = schemaOf(draft.protocol);

  // Every change builds on the latest state: files load asynchronously and
  // must not drop each other's values.
  const setDraft: Dispatch<SetStateAction<ProfileDraft>> = (update) =>
    setEditor((current) => ({
      ...current,
      draft: typeof update === 'function' ? update(current.draft) : update,
    }));

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

  const changeValues = (update: (values: FormValues) => FormValues) =>
    setEditor((current) =>
      withValues(schemaOf(current.draft.protocol), current, update(current.draft.values)),
    );

  const changeSecrets = (update: (secrets: SecretStates) => SecretStates) =>
    setDraft((current) => ({ ...current, secrets: update(current.secrets) }));

  const takeTemplateValues = (fieldKey: string) =>
    setEditor((current) => forcedTemplate(schemaOf(current.draft.protocol), current, fieldKey));

  const takeGeneratedSecret = (key: string, value: string) =>
    changeSecrets((secrets) => ({ ...secrets, [key]: typedSecret(secrets[key], value) }));

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
            onChange={(event) => {
              const name = event.currentTarget.value;
              setDraft((current) => ({ ...current, name }));
            }}
          />
          {!profile && (
            <ProtocolChooser
              available={drivers.map((driver) => driver.protocol)}
              value={draft.protocol}
              onChange={(protocol) =>
                setEditor((current) => ({
                  draft: { ...draftFor(protocol), name: current.draft.name },
                  templateKept: [],
                }))
              }
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
          onValuesChange={changeValues}
          onSecretsChange={changeSecrets}
          fieldAddons={{
            ...templateAddons({
              schema,
              values: draft.values,
              kept: templateKept,
              onForce: takeTemplateValues,
            }),
            ...schemaAddons(schema, {
              protocol: draft.protocol,
              values: draft.values,
              secrets: draft.secrets,
              profile,
              onGeneratedSecret: takeGeneratedSecret,
            }),
          }}
        />
      )}
      <ScheduleSection
        value={draft.dailyReconnect}
        timeZone={timeZone}
        error={fieldErrors?.dailyReconnectTime}
        onChange={(dailyReconnect) => setDraft((current) => ({ ...current, dailyReconnect }))}
      />
      <AccessSection
        publicAddress={draft.publicAddress}
        error={fieldErrors?.publicAddress}
        onChange={(publicAddress) => setDraft((current) => ({ ...current, publicAddress }))}
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

/** The state with new values; choosing a template pre-fills its presets into fields the user has not changed. */
function withValues(
  schema: FormSchema | undefined,
  state: EditorState,
  values: FormValues,
): EditorState {
  const before = state.draft.values;
  const choice = schema && changedTemplate(schema, before, values);
  if (!schema || !choice) {
    return { ...state, draft: { ...state.draft, values } };
  }
  const result = applyTemplate(schema, before, choice);
  return { draft: { ...state.draft, values: result.values }, templateKept: result.kept };
}

/** The state with all presets of the chosen template of `fieldKey` taken over. */
function forcedTemplate(
  schema: FormSchema | undefined,
  state: EditorState,
  fieldKey: string,
): EditorState {
  const values = state.draft.values;
  const field = schema && schemaFields(schema).find((candidate) => candidate.key === fieldKey);
  const option = field?.options?.find((candidate) => candidate.value === values[fieldKey]);
  if (!schema || !field || !option) return state;
  return {
    draft: { ...state.draft, values: forceTemplate(schema, values, { field, option }) },
    templateKept: [],
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
