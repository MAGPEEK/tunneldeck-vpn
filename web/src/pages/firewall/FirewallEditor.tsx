import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import { localizedFieldErrors } from '../../api/fieldErrors';
import {
  putFirewall,
  type FirewallRule,
  type FirewallSettings,
  type FirewallState,
} from '../../api/firewall';
import { queryKeys } from '../../api/queryKeys';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Notice } from '../../components/Notice';
import { Page } from '../../layout/Page';
import { useFirewallDevices } from '../../queries/queries';
import { genericErrorMessage } from '../auth/formError';
import styles from './FirewallPage.module.css';
import { HostContext } from './HostContext';
import { IntentCards } from './IntentCards';
import { intentDraft, intentOf, type EditorIntent, type Intent } from './intents';
import { IpsecTemplateForm } from './IpsecTemplateForm';
import { ProtectionCard } from './ProtectionCard';
import {
  draftsDiffer,
  duplicateDraft,
  errorsByDraft,
  invalidPortFields,
  matchesFilter,
  moveDraft,
  toDraft,
  toRule,
  type RuleDraft,
  type RuleFilter,
} from './ruleDraft';
import { RuleEditor } from './RuleEditor';
import { RuleList } from './RuleList';
import { ruleName, suggestedName, type RuleContext } from './ruleText';
import { detectService } from './services';

type Message = { kind: 'saved' } | { kind: 'templateAdded'; count: number };

/** The draft open in the step editor and the intent it is edited with. */
interface Editing {
  key: string;
  intent: EditorIntent;
  isNew: boolean;
}

/** What is open below the list: the intent cards or the IPsec form. */
type Panel = 'intents' | 'ipsec';

function settingsDiffer(a: FirewallSettings, b: FirewallSettings): boolean {
  return (
    a.dropInvalid !== b.dropInvalid ||
    a.mssClamp !== b.mssClamp ||
    a.synFloodProtection !== b.synFloodProtection ||
    a.pingLimit !== b.pingLimit
  );
}

/** Field errors for every draft whose port text cannot be sent. */
function localPortErrors(drafts: RuleDraft[], message: string) {
  const errors: Record<string, Record<string, string>> = {};
  for (const draft of drafts) {
    for (const field of invalidPortFields(draft)) {
      errors[draft.key] = { ...errors[draft.key], [field]: message };
    }
  }
  return errors;
}

export function FirewallEditor({ saved }: { saved: FirewallState }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const devices = useFirewallDevices();
  const [drafts, setDrafts] = useState(() => saved.rules.map((rule) => toDraft(rule)));
  const [settings, setSettings] = useState(saved.settings);
  const [filter, setFilter] = useState<RuleFilter>('all');
  const [editing, setEditing] = useState<Editing>();
  const [panel, setPanel] = useState<Panel>();
  const [errors, setErrors] = useState<Record<string, Record<string, string>>>({});
  const [errorRound, setErrorRound] = useState(0);
  const [message, setMessage] = useState<Message>();
  const context: RuleContext = { hostAddresses: saved.hostAddresses, devices: devices.data ?? [] };

  const reset = (state: FirewallState) => {
    setDrafts(state.rules.map((rule) => toDraft(rule)));
    setSettings(state.settings);
    setErrors({});
    setEditing(undefined);
    setPanel(undefined);
  };

  const edit = (draft: RuleDraft, intent?: EditorIntent, isNew = false) => {
    if (!matchesFilter(draft, filter)) setFilter('all');
    setPanel(undefined);
    setEditing({ key: draft.key, intent: intent ?? intentOf(draft, saved.hostAddresses), isNew });
  };

  const openFirst = (keys: string[], among: RuleDraft[]) => {
    const first = among.find((draft) => keys.includes(draft.key));
    if (first) {
      edit(first);
      setErrorRound((round) => round + 1);
    }
  };

  const save = useMutation({
    mutationFn: (sent: RuleDraft[]) =>
      putFirewall({ rules: sent.map((draft) => toRule(draft, saved.hostAddresses)), settings }),
    onSuccess: (state) => {
      client.setQueryData(queryKeys.firewall, state);
      reset(state);
      setMessage({ kind: 'saved' });
    },
    onError: (error, sent) => {
      if (isApiError(error) && error.code === 'validation_failed') {
        const byDraft = errorsByDraft(localizedFieldErrors(t, error), sent);
        setErrors(byDraft);
        openFirst(Object.keys(byDraft), sent);
      }
    },
  });

  const dirty =
    draftsDiffer(drafts, saved.rules, saved.hostAddresses) ||
    settingsDiffer(settings, saved.settings);

  const submit = () => {
    setMessage(undefined);
    const local = localPortErrors(drafts, t('firewall.editor.portFormat'));
    if (Object.keys(local).length > 0) {
      save.reset();
      setErrors(local);
      openFirst(Object.keys(local), drafts);
      return;
    }
    setErrors({});
    save.mutate(drafts);
  };

  const discard = () => {
    save.reset();
    setMessage(undefined);
    reset(saved);
  };

  const update = (key: string, change: Partial<RuleDraft>) =>
    setDrafts((current) => current.map((d) => (d.key === key ? { ...d, ...change } : d)));

  const choose = (intent: Intent) => {
    if (intent === 'ipsec') {
      setEditing(undefined);
      setPanel('ipsec');
      return;
    }
    const preset = intentDraft(intent, saved.hostAddress);
    const draft = {
      ...preset,
      name: suggestedName(t, preset, detectService(preset), context),
    };
    setDrafts((current) => [...current, draft]);
    edit(draft, intent, true);
  };

  const duplicate = (key: string) => {
    const index = drafts.findIndex((draft) => draft.key === key);
    const original = drafts[index];
    if (original === undefined) return;
    const copy = duplicateDraft(
      original,
      t('firewall.copyName', { name: ruleName(t, original) }).slice(0, 64),
    );
    setDrafts([...drafts.slice(0, index + 1), copy, ...drafts.slice(index + 1)]);
    edit(copy);
  };

  const remove = (key: string) => {
    setDrafts((current) => current.filter((draft) => draft.key !== key));
    if (editing?.key === key) setEditing(undefined);
  };

  const insertTemplate = (rules: FirewallRule[]) => {
    setDrafts((current) => [...current, ...rules.map((rule) => toDraft(rule, true))]);
    setPanel(undefined);
    setMessage({ kind: 'templateAdded', count: rules.length });
  };

  const editingDraft = drafts.find((draft) => draft.key === editing?.key);
  const failure = save.error;
  const errorKeys = new Set(Object.keys(errors));

  return (
    <Page
      title={t('pages.firewall.title')}
      actions={
        <>
          <Button disabled={!dirty || save.isPending} onClick={discard}>
            {t('firewall.discard')}
          </Button>
          <Button variant="primary" disabled={!dirty} loading={save.isPending} onClick={submit}>
            {t('firewall.save')}
          </Button>
        </>
      }
    >
      <div className={styles.stack}>
        <p>{t('firewall.explanation')}</p>
        <HostContext state={saved} />
        {isApiError(failure) && failure.code === 'firewall_failed' && (
          <Notice tone="danger" role="alert" title={t('firewall.failedTitle')}>
            <p>{t('firewall.failed')}</p>
            <p className={styles.detail}>{failure.message}</p>
          </Notice>
        )}
        {failure &&
          !(
            isApiError(failure) && ['firewall_failed', 'validation_failed'].includes(failure.code)
          ) && (
            <Notice tone="danger" role="alert">
              {genericErrorMessage(t, failure)}
            </Notice>
          )}
        {errorKeys.size > 0 && (
          <Notice tone="danger" role="alert">
            {t('firewall.invalid')}
          </Notice>
        )}
        {message?.kind === 'saved' && !dirty && (
          <Notice tone="info" role="status">
            {t('firewall.saved')}
          </Notice>
        )}
        {message?.kind === 'templateAdded' && (
          <Notice tone="info" role="status">
            {t('firewall.ipsec.added', { count: message.count })}
          </Notice>
        )}
        <Card
          title={t('firewall.rulesTitle')}
          actions={
            <Button
              icon={<Plus size={16} aria-hidden="true" />}
              aria-expanded={panel === 'intents'}
              onClick={() => {
                setEditing(undefined);
                setPanel(panel === 'intents' ? undefined : 'intents');
              }}
            >
              {t('firewall.addRule')}
            </Button>
          }
        >
          <div className={styles.tabBody}>
            <RuleList
              drafts={drafts}
              filter={filter}
              onFilter={setFilter}
              context={context}
              counters={saved.countersAvailable ? (saved.counters ?? {}) : undefined}
              errorKeys={errorKeys}
              editingKey={editing?.key}
              onChange={update}
              onMove={(key, step) =>
                setDrafts((current) =>
                  moveDraft(current, key, step, (draft) => matchesFilter(draft, filter)),
                )
              }
              onEdit={(key) => {
                const draft = drafts.find((candidate) => candidate.key === key);
                if (draft) edit(draft);
              }}
              onDuplicate={duplicate}
              onDelete={remove}
            />
            {panel === 'intents' && <IntentCards onChoose={choose} />}
            {panel === 'ipsec' && (
              <IpsecTemplateForm
                devices={devices.data}
                devicesFailed={devices.isError}
                hostAddresses={saved.hostAddresses}
                onInsert={insertTemplate}
                onCancel={() => setPanel(undefined)}
              />
            )}
            {editing && editingDraft && (
              <RuleEditor
                key={`${editingDraft.key}-${errorRound}`}
                draft={editingDraft}
                intent={editing.intent}
                isNew={editing.isNew}
                errors={errors[editingDraft.key] ?? {}}
                context={context}
                hostAddress={saved.hostAddress}
                lanSubnets={saved.lanSubnets}
                devicesFailed={devices.isError}
                onChange={(change) => update(editingDraft.key, change)}
                onDone={() => setEditing(undefined)}
                onCancel={() => remove(editingDraft.key)}
              />
            )}
          </div>
        </Card>
        <ProtectionCard settings={settings} onChange={setSettings} />
      </div>
    </Page>
  );
}
