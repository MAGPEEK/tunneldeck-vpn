import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { hasPorts, type FirewallProtocol } from '../../api/firewall';
import { Field } from '../../components/Field';
import fieldStyles from '../../components/Field.module.css';
import styles from './FirewallPage.module.css';
import type { RuleDraft } from './ruleDraft';
import { presetDetail, SERVICE_IDS, type ServiceId } from './services';

const PROTOCOLS: FirewallProtocol[] = ['tcp', 'udp', 'tcp+udp', 'icmp', 'esp', 'gre', 'any'];

export interface ServicePickerProps {
  draft: RuleDraft;
  service: ServiceId;
  errors: Record<string, string>;
  onService: (service: ServiceId) => void;
  onChange: (change: Partial<RuleDraft>) => void;
}

/** Step 2 of the editor: a preset, or "Custom" with protocol and port fields. */
export function ServicePicker({ draft, service, errors, onService, onChange }: ServicePickerProps) {
  const { t } = useTranslation();
  const name = useId();
  const serviceError = errors.protocol ?? errors.destinationPort ?? errors.icmpType;
  return (
    <div className={styles.picker}>
      <div className={styles.presets} role="radiogroup" aria-label={t('firewall.step.service')}>
        {SERVICE_IDS.map((id) => {
          const detail = presetDetail(id);
          return (
            <label key={id} className={styles.preset}>
              <input
                type="radio"
                name={name}
                checked={service === id}
                onChange={() => onService(id)}
              />
              <span>{t(`firewall.service.${id}`)}</span>
              {detail !== undefined && <span className={styles.presetDetail}>{detail}</span>}
            </label>
          );
        })}
      </div>
      {service === 'custom' && <CustomService draft={draft} errors={errors} onChange={onChange} />}
      {service !== 'custom' && serviceError !== undefined && (
        <p className={fieldStyles.error}>{serviceError}</p>
      )}
    </div>
  );
}

interface CustomServiceProps {
  draft: RuleDraft;
  errors: Record<string, string>;
  onChange: (change: Partial<RuleDraft>) => void;
}

function CustomService({ draft, errors, onChange }: CustomServiceProps) {
  const { t } = useTranslation();
  return (
    <div className={styles.editorGrid}>
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
      {hasPorts(draft.protocol) && (
        <PortField
          label={t('firewall.editor.destinationPort')}
          value={draft.destinationPort}
          error={errors.destinationPort}
          onChange={(destinationPort) => onChange({ destinationPort })}
        />
      )}
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
  );
}

export interface PortFieldProps {
  label: string;
  value: string;
  hint?: string;
  placeholder?: string;
  disabled?: boolean;
  error: string | undefined;
  onChange: (value: string) => void;
}

/** A port or range; empty means any port. */
export function PortField({
  label,
  value,
  hint,
  placeholder,
  disabled,
  error,
  onChange,
}: PortFieldProps) {
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
