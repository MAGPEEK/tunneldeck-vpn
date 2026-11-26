import { useId, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { hasPorts, type FirewallAction, type FirewallDirection } from '../../api/firewall';
import { Button } from '../../components/Button';
import { Field } from '../../components/Field';
import fieldStyles from '../../components/Field.module.css';
import { Notice } from '../../components/Notice';
import { DevicePicker } from './DevicePicker';
import styles from './FirewallPage.module.css';
import { FlowStrip } from './FlowStrip';
import { editorSteps, type EditorIntent, type EditorStep } from './intents';
import { firstLanExample } from './lanExample';
import { isPortForward, type RuleDraft } from './ruleDraft';
import { ruleCreates, ruleSummary } from './ruleSummary';
import { suggestedName, type RuleContext } from './ruleText';
import { PortField, ServicePicker } from './ServicePicker';
import { detectService, serviceChange, type ServiceId } from './services';

/** API field names the editor shows next to a control; others are listed on top. */
const SHOWN_FIELDS = new Set([
  'name',
  'direction',
  'action',
  'protocol',
  'icmpType',
  'source',
  'sourcePort',
  'destination',
  'destinationPort',
  'publicPort',
  'keepSourceAddress',
  'comment',
]);

/** Fields inside "Restrict and advanced", which opens when one of them has an error. */
const ADVANCED_FIELDS = ['source', 'sourcePort', 'publicPort', 'keepSourceAddress', 'comment'];

const SERVICE_FIELDS = ['protocol', 'destinationPort', 'icmpType'];

export interface RuleEditorProps {
  draft: RuleDraft;
  intent: EditorIntent;
  /** Created from an intent card in this editing session. */
  isNew: boolean;
  errors: Record<string, string>;
  context: RuleContext;
  hostAddress: string;
  lanSubnets: readonly string[];
  devicesFailed: boolean;
  onChange: (change: Partial<RuleDraft>) => void;
  onDone: () => void;
  onCancel: () => void;
}

/** The inline step editor of SPEC §16.4: live flow strip, numbered steps, summary. */
export function RuleEditor(props: RuleEditorProps) {
  const { draft, intent, isNew, errors, context, onChange } = props;
  const { t } = useTranslation();
  const titleId = useId();
  const hasError = (fields: string[]) => fields.some((field) => errors[field] !== undefined);
  const [service, setService] = useState<ServiceId>(() =>
    hasError(SERVICE_FIELDS) ? 'custom' : detectService(draft),
  );
  const [nameTouched, setNameTouched] = useState(!isNew);
  const [advancedOpen, setAdvancedOpen] = useState(() => hasError(ADVANCED_FIELDS));
  const other = Object.entries(errors).filter(([field]) => !SHOWN_FIELDS.has(field));

  const change = (patch: Partial<RuleDraft>, nextService: ServiceId = service) => {
    const next = { ...draft, ...patch };
    onChange(
      nameTouched ? patch : { ...patch, name: suggestedName(t, next, nextService, context) },
    );
  };
  const chooseService = (id: ServiceId) => {
    setService(id);
    change(serviceChange(id, draft), id);
  };

  const steps = editorSteps(intent, draft);
  const stepBody: Record<EditorStep, () => ReactNode> = {
    rule: () => <RuleStep {...props} onChange={change} />,
    device: () => <DeviceStep {...props} onChange={change} />,
    destination: () => (
      <Field
        label={t('firewall.editor.destinationOutbound')}
        hint={t('firewall.editor.destinationOutboundHint')}
        placeholder={t('firewall.editor.destinationOutboundPlaceholder')}
        className={styles.monoField}
        value={draft.destination}
        spellCheck={false}
        error={errors.destination}
        onChange={(event) => change({ destination: event.currentTarget.value })}
      />
    ),
    service: () => (
      <ServicePicker
        draft={draft}
        service={service}
        errors={errors}
        onService={chooseService}
        onChange={change}
      />
    ),
    name: () => (
      <Field
        label={t('firewall.editor.name')}
        value={draft.name}
        maxLength={64}
        required
        error={errors.name}
        onChange={(event) => {
          setNameTouched(true);
          onChange({ name: event.currentTarget.value });
        }}
      />
    ),
  };

  return (
    <section className={styles.editor} aria-labelledby={titleId}>
      <h3 id={titleId} className={styles.editorTitle}>
        {isNew ? t(`firewall.intent.${intent}.title`) : t('firewall.editor.title')}
      </h3>
      <FlowStrip draft={draft} context={context} />
      {other.length > 0 && (
        <Notice tone="danger">
          {other.map(([field, message]) => (
            <p key={field}>{message}</p>
          ))}
        </Notice>
      )}
      <ol className={styles.steps}>
        {steps.map((step, index) => (
          <li key={step} className={styles.step}>
            <fieldset className={styles.stepSet}>
              <legend className={styles.stepLegend}>
                <span className={styles.stepNumber} aria-hidden="true">
                  {index + 1}
                </span>
                {t(`firewall.step.${step}`)}
              </legend>
              {stepBody[step]()}
            </fieldset>
          </li>
        ))}
      </ol>
      <div className={styles.summary} aria-live="polite">
        <h4 className={styles.summaryTitle}>{t('firewall.editor.summary')}</h4>
        {ruleSummary(t, draft, context).map((sentence) => (
          <p key={sentence}>{sentence}</p>
        ))}
      </div>
      <details
        className={styles.details}
        open={advancedOpen}
        onToggle={(event) => setAdvancedOpen(event.currentTarget.open)}
      >
        <summary>{t('firewall.editor.advanced')}</summary>
        <AdvancedFields draft={draft} errors={errors} context={context} onChange={change} />
      </details>
      <details className={styles.details}>
        <summary>{t('firewall.editor.creates')}</summary>
        <ul className={styles.creates}>
          {ruleCreates(t, draft, context).map((entry) => (
            <li key={entry}>{entry}</li>
          ))}
        </ul>
      </details>
      <div className={styles.editorButtons}>
        {isNew && <Button onClick={props.onCancel}>{t('firewall.editor.cancel')}</Button>}
        <Button onClick={props.onDone}>{t('firewall.editor.done')}</Button>
      </div>
    </section>
  );
}

const DIRECTIONS: FirewallDirection[] = ['inbound', 'outbound'];

/** Direction and action for a custom rule; drop or reject for a block. */
function RuleStep({ draft, intent, errors, context, onChange }: RuleEditorProps) {
  const { t } = useTranslation();
  const forward = isPortForward(draft, context.hostAddresses);
  const actions: FirewallAction[] =
    intent === 'block' ? ['drop', 'reject'] : ['accept', 'drop', 'reject'];
  return (
    <div className={styles.editorGrid}>
      {intent === 'custom' && (
        <Field label={t('firewall.editor.direction')} error={errors.direction}>
          {(control) => (
            <select
              {...control}
              value={draft.direction}
              onChange={(event) =>
                onChange({ direction: event.currentTarget.value as FirewallDirection })
              }
            >
              {DIRECTIONS.map((direction) => (
                <option key={direction} value={direction}>
                  {t(`firewall.direction.${direction}`)}
                </option>
              ))}
            </select>
          )}
        </Field>
      )}
      <Field
        label={t('firewall.editor.action')}
        hint={forward ? t('firewall.editor.actionForwardHint') : undefined}
        error={errors.action}
      >
        {(control) => (
          <select
            {...control}
            value={forward ? 'accept' : draft.action}
            disabled={forward}
            onChange={(event) => onChange({ action: event.currentTarget.value as FirewallAction })}
          >
            {actions.map((action) => (
              <option key={action} value={action}>
                {t(`firewall.action.${action}`)}
              </option>
            ))}
          </select>
        )}
      </Field>
    </div>
  );
}

/** Inbound: the LAN device traffic goes to. Outbound: the device or subnet it comes from. */
function DeviceStep(props: RuleEditorProps) {
  const { draft, errors, context, hostAddress, lanSubnets, onChange } = props;
  const { t } = useTranslation();
  const example = firstLanExample(lanSubnets);
  if (draft.direction === 'outbound') {
    const subnet = lanSubnets[0];
    return (
      <DevicePicker
        label={t('firewall.device.sourceLabel')}
        value={draft.source}
        onChange={(source) => onChange({ source })}
        devices={context.devices}
        devicesFailed={props.devicesFailed}
        hostAddress=""
        hostAddresses={context.hostAddresses}
        lanSubnets={lanSubnets}
        placeholder={
          example !== undefined && subnet !== undefined
            ? t('firewall.device.sourcePlaceholder', { device: example, subnet })
            : t('firewall.device.sourcePlaceholderNeutral')
        }
        hint={t('firewall.device.gatewayHint')}
        error={errors.source}
      />
    );
  }
  return (
    <DevicePicker
      label={t('firewall.device.label')}
      value={draft.destination}
      onChange={(destination) => onChange({ destination })}
      devices={context.devices}
      devicesFailed={props.devicesFailed}
      hostAddress={hostAddress}
      hostAddresses={context.hostAddresses}
      placeholder={example ?? t('firewall.device.addressPlaceholder')}
      hint={
        lanSubnets.length > 0
          ? t('firewall.device.lanHint', { subnets: lanSubnets.join(', ') })
          : undefined
      }
      error={errors.destination}
    />
  );
}

interface AdvancedFieldsProps {
  draft: RuleDraft;
  errors: Record<string, string>;
  context: RuleContext;
  onChange: (change: Partial<RuleDraft>) => void;
}

/** Sender, port on the VPN address, the sender the device sees, comment. Empty = any. */
function AdvancedFields({ draft, errors, context, onChange }: AdvancedFieldsProps) {
  const { t } = useTranslation();
  const inbound = draft.direction === 'inbound';
  const forward = isPortForward(draft, context.hostAddresses);
  const ports = hasPorts(draft.protocol);
  const anyPort = draft.destinationPort.trim() === '';
  return (
    <div className={styles.advanced}>
      <div className={styles.editorGrid}>
        {inbound && (
          <Field
            label={t('firewall.editor.source')}
            placeholder={t('firewall.editor.sourcePlaceholder')}
            className={styles.monoField}
            value={draft.source}
            spellCheck={false}
            error={errors.source}
            onChange={(event) => onChange({ source: event.currentTarget.value })}
          />
        )}
        {ports && (
          <PortField
            label={t('firewall.editor.sourcePort')}
            value={draft.sourcePort}
            error={errors.sourcePort}
            onChange={(sourcePort) => onChange({ sourcePort })}
          />
        )}
        {forward && ports && (
          <PortField
            label={t('firewall.editor.publicPort')}
            hint={t(
              anyPort ? 'firewall.editor.publicPortAnyHint' : 'firewall.editor.publicPortHint',
            )}
            value={anyPort ? '' : draft.publicPort}
            placeholder={draft.destinationPort.trim() || undefined}
            disabled={anyPort}
            error={errors.publicPort}
            onChange={(publicPort) => onChange({ publicPort })}
          />
        )}
      </div>
      {forward && <SenderSeen draft={draft} error={errors.keepSourceAddress} onChange={onChange} />}
      <Field
        label={t('firewall.editor.comment')}
        value={draft.comment}
        error={errors.comment}
        onChange={(event) => onChange({ comment: event.currentTarget.value })}
      />
    </div>
  );
}

interface SenderSeenProps {
  draft: RuleDraft;
  error: string | undefined;
  onChange: (change: Partial<RuleDraft>) => void;
}

/** "Sender seen by the device: this device / original" (= keepSourceAddress). */
function SenderSeen({ draft, error, onChange }: SenderSeenProps) {
  const { t } = useTranslation();
  const name = useId();
  const options = [
    { keep: false, label: t('firewall.editor.senderHost') },
    { keep: true, label: t('firewall.editor.senderOriginal') },
  ];
  return (
    <fieldset className={styles.stepSet} aria-describedby={`${name}-hint`}>
      <legend className={fieldStyles.label}>{t('firewall.editor.senderSeen')}</legend>
      <div className={styles.presets}>
        {options.map((option) => (
          <label key={String(option.keep)} className={styles.preset}>
            <input
              type="radio"
              name={name}
              checked={draft.keepSourceAddress === option.keep}
              onChange={() => onChange({ keepSourceAddress: option.keep })}
            />
            {option.label}
          </label>
        ))}
      </div>
      <p id={`${name}-hint`} className={fieldStyles.hint}>
        {t(
          draft.keepSourceAddress
            ? 'firewall.editor.senderOriginalHint'
            : 'firewall.editor.senderHostHint',
        )}
      </p>
      {error && <p className={fieldStyles.error}>{error}</p>}
    </fieldset>
  );
}
