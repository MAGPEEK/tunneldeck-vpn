import { useMutation } from '@tanstack/react-query';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../../api/client';
import { ipsecTemplate, type FirewallRule } from '../../api/firewall';
import { Button } from '../../components/Button';
import { Field } from '../../components/Field';
import { Notice } from '../../components/Notice';
import { genericErrorMessage } from '../auth/formError';
import { StringListField } from '../profiles/schema/StringListField';
import styles from './FirewallPage.module.css';

export interface IpsecTemplateFormProps {
  onInsert: (rules: FirewallRule[]) => void;
  onCancel: () => void;
}

/** The "IPsec device" template (SPEC §16.2): asks the server for the rules and hands them over. */
export function IpsecTemplateForm({ onInsert, onCancel }: IpsecTemplateFormProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const [name, setName] = useState('');
  const [deviceAddress, setDeviceAddress] = useState('');
  const [peers, setPeers] = useState<string[]>([]);
  const create = useMutation({ mutationFn: ipsecTemplate, onSuccess: onInsert });
  const fields = isApiError(create.error) ? create.error.fields : {};
  const peerErrors = Object.entries(fields)
    .filter(([key]) => key.startsWith('peers['))
    .map(([, message]) => message);
  const failure =
    create.error && !(isApiError(create.error) && create.error.code === 'validation_failed');

  return (
    <form
      className={styles.editor}
      aria-labelledby={titleId}
      onSubmit={(event) => {
        event.preventDefault();
        create.mutate({
          name: name.trim(),
          deviceAddress: deviceAddress.trim(),
          peers: peers.map((peer) => peer.trim()).filter((peer) => peer !== ''),
        });
      }}
    >
      <h3 id={titleId} className={styles.editorTitle}>
        {t('firewall.ipsec.title')}
      </h3>
      <p className={styles.secondary}>{t('firewall.ipsec.intro')}</p>
      {failure && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, create.error)}
        </Notice>
      )}
      <div className={styles.editorGrid}>
        <Field
          label={t('firewall.ipsec.name')}
          placeholder={t('firewall.ipsec.namePlaceholder')}
          value={name}
          required
          error={fields.name}
          onChange={(event) => setName(event.currentTarget.value)}
        />
        <Field
          label={t('firewall.ipsec.device')}
          placeholder={t('firewall.ipsec.devicePlaceholder')}
          className={styles.monoField}
          value={deviceAddress}
          required
          spellCheck={false}
          error={fields.deviceAddress}
          onChange={(event) => setDeviceAddress(event.currentTarget.value)}
        />
      </div>
      <StringListField
        label={t('firewall.ipsec.peers')}
        lines={peers}
        placeholder="203.0.113.7"
        error={peerErrors.length > 0 ? peerErrors.join(' ') : undefined}
        onChange={setPeers}
      />
      <div className={styles.editorButtons}>
        <Button onClick={onCancel}>{t('firewall.ipsec.cancel')}</Button>
        <Button type="submit" loading={create.isPending}>
          {t('firewall.ipsec.submit')}
        </Button>
      </div>
    </form>
  );
}
