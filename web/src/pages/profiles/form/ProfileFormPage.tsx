import { useQueryClient } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useParams } from 'react-router';
import type { Driver, ImportDraft, Profile } from '../../../api/profiles';
import { queryKeys } from '../../../api/queryKeys';
import { Notice } from '../../../components/Notice';
import { Page } from '../../../layout/Page';
import { useDrivers, useProfile, useSystem } from '../../../queries/queries';
import { genericErrorMessage } from '../../auth/formError';
import { readProfileFormState } from '../profileFormState';
import { initialSecrets, initialValues } from '../schema/schemaValues';
import { ProfileEditor, type ProfileDraft } from './ProfileEditor';

const DEFAULT_DAILY = { enabled: false, time: '04:00' };

function emptyDraft(drivers: Driver[], protocol: string): ProfileDraft {
  const schema = drivers.find((driver) => driver.protocol === protocol)?.schema ?? { sections: [] };
  return {
    name: '',
    protocol,
    values: initialValues(schema),
    secrets: initialSecrets(schema),
    dailyReconnect: DEFAULT_DAILY,
  };
}

function draftFromProfile(drivers: Driver[], profile: Profile, keepSecrets: boolean): ProfileDraft {
  const schema = drivers.find((driver) => driver.protocol === profile.protocol)?.schema ?? {
    sections: [],
  };
  return {
    name: profile.name,
    protocol: profile.protocol,
    values: initialValues(schema, profile.settings),
    secrets: initialSecrets(schema, keepSecrets ? profile.secrets : {}),
    dailyReconnect: profile.dailyReconnect,
  };
}

function draftFromImport(drivers: Driver[], protocol: string, imported: ImportDraft): ProfileDraft {
  const schema = drivers.find((driver) => driver.protocol === protocol)?.schema ?? { sections: [] };
  return {
    ...emptyDraft(drivers, protocol),
    values: initialValues(schema, imported.settings),
    secrets: initialSecrets(schema, {}, imported.secrets),
  };
}

function copyName(t: TFunction, name: string): string {
  return t('profileForm.copyName', { name }).slice(0, 64);
}

/** /profiles/new (blank, duplicate or import) and /profiles/:id; each navigation starts fresh. */
export function ProfileFormPage() {
  const location = useLocation();
  return <ProfileFormView key={location.key} />;
}

function ProfileFormView() {
  const { t } = useTranslation();
  const { id } = useParams();
  const location = useLocation();
  const client = useQueryClient();
  const [state] = useState(() => readProfileFormState(location.state));
  const [imported] = useState(() =>
    state.fromImport ? client.getQueryData<ImportDraft>(queryKeys.importDraft) : undefined,
  );
  const drivers = useDrivers();
  const system = useSystem();
  const profile = useProfile(id);
  const source = useProfile(id === undefined ? state.duplicateOf : undefined);

  const title = id === undefined ? t('profileForm.newTitle') : t('profileForm.editTitle');
  const error = drivers.error ?? profile.error ?? source.error;
  if (error) {
    return (
      <Page title={title}>
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, error)}
        </Notice>
      </Page>
    );
  }
  const loading =
    !drivers.data ||
    (id !== undefined && !profile.data) ||
    (state.duplicateOf !== undefined && id === undefined && !source.data);
  if (loading) {
    return (
      <Page title={title}>
        <p aria-busy="true">{t('session.loading')}</p>
      </Page>
    );
  }

  const driverList = drivers.data;
  const firstProtocol = driverList[0]?.protocol ?? 'openvpn';
  const draftFor = (protocol: string) => emptyDraft(driverList, protocol);
  let initial: ProfileDraft;
  let notice: string | undefined;
  if (profile.data) {
    initial = draftFromProfile(driverList, profile.data, true);
  } else if (source.data) {
    initial = {
      ...draftFromProfile(driverList, source.data, false),
      name: copyName(t, source.data.name),
    };
    notice = t('profileForm.duplicateNotice');
  } else if (imported) {
    initial = draftFromImport(driverList, firstProtocol, imported);
  } else {
    initial = draftFor(firstProtocol);
  }

  return (
    <Page title={title}>
      <ProfileEditor
        key={profile.data?.id ?? 'new'}
        profile={profile.data}
        initial={initial}
        drivers={driverList}
        timeZone={system.data?.timeZone}
        importWarnings={id === undefined ? imported?.warnings : undefined}
        notice={notice}
        justSaved={state.saved}
        draftFor={draftFor}
      />
    </Page>
  );
}
