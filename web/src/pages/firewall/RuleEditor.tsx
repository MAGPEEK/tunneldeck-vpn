import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import type { FirewallAction, FirewallProtocol } from '../../api/firewall';
import { Button } from '../../components/Button';
import { Field } from '../../components/Field';
import fieldStyles from '../../components/Field.module.css';
import { Notice } from '../../components/Notice';
import styles from './FirewallPage.module.css';
import { isPortForward, isToHost, visiblePortFields, type RuleDraft } from './ruleDraft';

const ACTIONS: FirewallAction[] = ['accept', 'drop', 'reject'];
const PROTOCOLS: FirewallProtocol[] = ['tcp', 'udp', 'tcp+udp', 'icmp', 'esp', 'gre', 'any'];

/** API field names the editor shows next to a control; others are listed on top. */
const SHOWN_FIELDS = new Set([
  'name',
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

export interface RuleEditorProps {
  draft: RuleDraft;
  errors: Record<string, string>;
  hostAddress: string;
  hostAddresses: readonly string[];
  lanSubnets: string[];
  onChange: (change: Partial<RuleDraft>) => void;
  onDone: () => void;
}

export function RuleEditor({
  draft,
  errors,
  hostAddress,
  hostAddresses,
  lanSubnets,
  onChange,
  onDone,
}: RuleEditorProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const inbound = draft.direction === 'inbound';
  const forward = isPortForward(draft, hostAddresses);
  const ports = visiblePortFields(draft);
  const other = Object.entries(errors).filter(([field]) => !SHOWN_FIELDS.has(field));

  return (
    <section className={styles.editor} aria-labelledby={titleId}>
      <h3 id={titleId} className={styles.editorTitle}>
        {t('firewall.editor.title')}
      </h3>
      {other.length > 0 && (
        <Notice tone="danger">
          {other.map(([field, message]) => (
            <p key={field}>{message}</p>
          ))}
        </Notice>
      )}
      <div className={styles.editorGrid}>
        <Field
          label={t('firewall.editor.name')}
          value={draft.name}
          maxLength={64}
          required
          error={errors.name}
          onChange={(event) => onChange({ name: event.currentTarget.value })}
        />
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
              onChange={(event) =>
                onChange({ action: event.currentTarget.value as FirewallAction })
              }
            >
              {ACTIONS.map((action) => (
                <option key={action} value={action}>
                  {t(`firewall.action.${action}`)}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t('firewall.editor.protocol')} error={errors.protocol}>
          {(control) => (
            <select
              {...control}
              value={draft.protocol}
              onChange={(event) =>
                onChange({ protocol: event.currentTarget.value as FirewallProtocol })
              }
            >
              {PROTOCOLS.map((protocol) => (
                <option key={protocol} value={protocol}>
                  {t(`firewall.protocol.${protocol}`)}
                </option>
              ))}
            </select>
          )}
        </Field>
        {draft.protocol === 'icmp' && (
          <Field
            label={t('firewall.editor.icmpType')}
            hint={t('firewall.editor.icmpTypeHint')}
            className={styles.monoField}
            value={draft.icmpType}
            spellCheck={false}
            error={errors.icmpType}
            onChange={(event) => onChange({ icmpType: event.currentTarget.value })}
          />
        )}
      </div>

      <div className={styles.editorGrid}>
        <Field
          label={t(inbound ? 'firewall.editor.source' : 'firewall.editor.sourceOutbound')}
          placeholder={t(
            inbound
              ? 'firewall.editor.sourcePlaceholder'
              : 'firewall.editor.sourceOutboundPlaceholder',
          )}
          className={styles.monoField}
          value={draft.source}
          required={!inbound}
          spellCheck={false}
          error={errors.source}
          onChange={(event) => onChange({ source: event.currentTarget.value })}
        />
        {ports.includes('sourcePort') && (
          <PortInput
            label={t('firewall.editor.sourcePort')}
            value={draft.sourcePort}
            error={errors.sourcePort}
            onChange={(sourcePort) => onChange({ sourcePort })}
          />
        )}
      </div>

      {inbound ? (
        <InboundDestination
          draft={draft}
          errors={errors}
          hostAddress={hostAddress}
          hostAddresses={hostAddresses}
          lanSubnets={lanSubnets}
          onChange={onChange}
        />
      ) : (
        <div className={styles.editorGrid}>
          <Field
            label={t('firewall.editor.destinationOutbound')}
            placeholder={t('firewall.editor.destinationOutboundPlaceholder')}
            className={styles.monoField}
            value={draft.destination}
            required
            spellCheck={false}
            error={errors.destination}
            onChange={(event) => onChange({ destination: event.currentTarget.value })}
          />
          {ports.includes('destinationPort') && (
            <PortInput
              label={t('firewall.editor.destinationPort')}
              value={draft.destinationPort}
              error={errors.destinationPort}
              onChange={(destinationPort) => onChange({ destinationPort })}
            />
          )}
        </div>
      )}

      <Field
        label={t('firewall.editor.comment')}
        value={draft.comment}
        error={errors.comment}
        onChange={(event) => onChange({ comment: event.currentTarget.value })}
      />
      <div className={styles.editorButtons}>
        <Button onClick={onDone}>{t('firewall.editor.done')}</Button>
      </div>
    </section>
  );
}

interface InboundDestinationProps {
  draft: RuleDraft;
  errors: Record<string, string>;
  hostAddress: string;
  hostAddresses: readonly string[];
  lanSubnets: string[];
  onChange: (change: Partial<RuleDraft>) => void;
}

function InboundDestination({
  draft,
  errors,
  hostAddress,
  hostAddresses,
  lanSubnets,
  onChange,
}: InboundDestinationProps) {
  const { t } = useTranslation();
  const name = useId();
  const toHost = isToHost(draft, hostAddresses);
  const ports = visiblePortFields(draft);
  const anyPort = draft.destinationPort.trim() === '';
  const publicPortDisabled = toHost || anyPort;
  const suggestHost = hostAddress !== '' && draft.destination.trim() !== hostAddress;
  return (
    <>
      <div className={styles.editorGrid}>
        <div>
          <Field
            label={t('firewall.editor.destination')}
            hint={
              lanSubnets.length > 0
                ? t('firewall.editor.lanHint', { subnets: lanSubnets.join(', ') })
                : undefined
            }
            placeholder="192.168.1.10"
            className={styles.monoField}
            value={draft.destination}
            required
            spellCheck={false}
            error={errors.destination}
            onChange={(event) => onChange({ destination: event.currentTarget.value })}
          />
          {suggestHost && (
            <Button variant="ghost" onClick={() => onChange({ destination: hostAddress })}>
              {t('firewall.editor.useHostAddress', { address: hostAddress })}
            </Button>
          )}
        </div>
        {ports.includes('destinationPort') && (
          <PortInput
            label={t('firewall.editor.destinationPort')}
            hint={!toHost && anyPort ? t('firewall.editor.anyPortForwardHint') : undefined}
            value={draft.destinationPort}
            error={errors.destinationPort}
            onChange={(destinationPort) => onChange({ destinationPort })}
          />
        )}
        {ports.includes('publicPort') && (
          <PortInput
            label={t('firewall.editor.publicPort')}
            hint={t(
              toHost ? 'firewall.editor.publicPortHostHint' : 'firewall.editor.publicPortHint',
            )}
            value={publicPortDisabled ? '' : draft.publicPort}
            placeholder={draft.destinationPort.trim() || undefined}
            disabled={publicPortDisabled}
            error={errors.publicPort}
            onChange={(publicPort) => onChange({ publicPort })}
          />
        )}
      </div>
      {!toHost && (
        <div className={styles.checkboxField}>
          <label className={styles.choice}>
            <input
              type="checkbox"
              checked={draft.keepSourceAddress}
              aria-describedby={`${name}-keep-hint`}
              onChange={(event) => onChange({ keepSourceAddress: event.currentTarget.checked })}
            />
            {t('firewall.editor.keepSource')}
          </label>
          <p id={`${name}-keep-hint`} className={fieldStyles.hint}>
            {t('firewall.editor.keepSourceHint')}
          </p>
          {errors.keepSourceAddress && (
            <p className={fieldStyles.error}>{errors.keepSourceAddress}</p>
          )}
        </div>
      )}
    </>
  );
}

interface PortInputProps {
  label: string;
  value: string;
  hint?: string;
  placeholder?: string;
  disabled?: boolean;
  error: string | undefined;
  onChange: (value: string) => void;
}

function PortInput({ label, value, hint, placeholder, disabled, error, onChange }: PortInputProps) {
  const { t } = useTranslation();
  return (
    <Field
      label={label}
      hint={hint}
      className={styles.monoField}
      value={value}
      inputMode="numeric"
      placeholder={placeholder ?? t('firewall.editor.portPlaceholder')}
      disabled={disabled}
      spellCheck={false}
      error={error}
      onChange={(event) => onChange(event.currentTarget.value)}
    />
  );
}
