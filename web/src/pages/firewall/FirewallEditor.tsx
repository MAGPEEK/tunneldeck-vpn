import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import {
  putFirewall,
  type FirewallDirection,
  type FirewallRule,
  type FirewallSettings,
  type FirewallState,
} from '../../api/firewall';
import { queryKeys } from '../../api/queryKeys';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Notice } from '../../components/Notice';
import { Page } from '../../layout/Page';
import { genericErrorMessage } from '../auth/formError';
import { DirectionTabs } from './DirectionTabs';
import styles from './FirewallPage.module.css';
import { HostContext } from './HostContext';
import { IpsecTemplateForm } from './IpsecTemplateForm';
import { ProtectionCard } from './ProtectionCard';
import {
  draftsDiffer,
  duplicateDraft,
  errorsByDraft,
  invalidPortFields,
  moveDraft,
  newDraft,
  toDraft,
  toRule,
  type RuleDraft,
} from './ruleDraft';
import { RuleEditor } from './RuleEditor';
import { RuleTable } from './RuleTable';
import { ruleName } from './ruleText';

type Message = { kind: 'saved' } | { kind: 'templateAdded'; count: number };

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
  const [drafts, setDrafts] = useState(() => saved.rules.map((rule) => toDraft(rule)));
  const [settings, setSettings] = useState(saved.settings);
  const [tab, setTab] = useState<FirewallDirection>('inbound');
  const [editingKey, setEditingKey] = useState<string>();
  const [templateOpen, setTemplateOpen] = useState(false);
  const [errors, setErrors] = useState<Record<string, Record<string, string>>>({});
  const [message, setMessage] = useState<Message>();

  const reset = (state: FirewallState) => {
    setDrafts(state.rules.map((rule) => toDraft(rule)));
    setSettings(state.settings);
    setErrors({});
    setEditingKey(undefined);
    setTemplateOpen(false);
  };

  const openFirst = (keys: string[], among: RuleDraft[]) => {
    const first = among.find((draft) => keys.includes(draft.key));
    if (first) {
      setTab(first.direction);
      setEditingKey(first.key);
      setTemplateOpen(false);
    }
  };

  const save = useMutation({
    mutationFn: (sent: RuleDraft[]) => putFirewall({ rules: sent.map(toRule), settings }),
    onSuccess: (state) => {
      client.setQueryData(queryKeys.firewall, state);
      reset(state);
      setMessage({ kind: 'saved' });
    },
    onError: (error, sent) => {
      if (isApiError(error) && error.code === 'validation_failed') {
        const byDraft = errorsByDraft(error.fields, sent);
        setErrors(byDraft);
        openFirst(Object.keys(byDraft), sent);
      }
    },
  });

  const dirty = draftsDiffer(drafts, saved.rules) || settingsDiffer(settings, saved.settings);

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

  const add = () => {
    const draft = newDraft(tab);
    setDrafts((current) => [...current, draft]);
    setTemplateOpen(false);
    setEditingKey(draft.key);
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
    setTemplateOpen(false);
    setEditingKey(copy.key);
  };

  const remove = (key: string) => {
    setDrafts((current) => current.filter((draft) => draft.key !== key));
    if (editingKey === key) setEditingKey(undefined);
  };

  const insertTemplate = (rules: FirewallRule[]) => {
    setDrafts((current) => [...current, ...rules.map((rule) => toDraft(rule, true))]);
    setTemplateOpen(false);
    setMessage({ kind: 'templateAdded', count: rules.length });
  };

  const editing = drafts.find((draft) => draft.key === editingKey && draft.direction === tab);
  const visible = drafts.filter((draft) => draft.direction === tab);
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
        <Card>
          <DirectionTabs
            selected={tab}
            onSelect={(direction) => {
              setTab(direction);
              setTemplateOpen(false);
            }}
          >
            <div className={styles.tabBody}>
              {tab === 'outbound' && <Notice tone="info">{t('firewall.outboundHint')}</Notice>}
              <RuleTable
                direction={tab}
                drafts={visible}
                errorKeys={errorKeys}
                onChange={update}
                onMove={(key, step) => setDrafts((current) => moveDraft(current, key, step))}
                onEdit={(key) => {
                  setTemplateOpen(false);
                  setEditingKey(key);
                }}
                onDuplicate={duplicate}
                onDelete={remove}
              />
              <div className={styles.tabButtons}>
                <Button icon={<Plus size={16} aria-hidden="true" />} onClick={add}>
                  {t('firewall.addRule')}
                </Button>
                {tab === 'inbound' && (
                  <Button
                    onClick={() => {
                      setEditingKey(undefined);
                      setTemplateOpen(true);
                    }}
                  >
                    {t('firewall.ipsec.open')}
                  </Button>
                )}
              </div>
              {editing && (
                <RuleEditor
                  key={editing.key}
                  draft={editing}
                  errors={errors[editing.key] ?? {}}
                  hostAddress={saved.hostAddress}
                  lanSubnets={saved.lanSubnets}
                  onChange={(change) => update(editing.key, change)}
                  onDone={() => setEditingKey(undefined)}
                />
              )}
              {templateOpen && tab === 'inbound' && (
                <IpsecTemplateForm
                  onInsert={insertTemplate}
                  onCancel={() => setTemplateOpen(false)}
                />
              )}
            </div>
          </DirectionTabs>
        </Card>
        <ProtectionCard settings={settings} onChange={setSettings} />
      </div>
    </Page>
  );
}
