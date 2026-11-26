import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { generateKeyPair, type KeyPair } from '../../../api/profiles';
import { Button } from '../../../components/Button';
import { CopyButton } from '../../../components/CopyButton';
import { Field } from '../../../components/Field';
import { Notice } from '../../../components/Notice';
import { genericErrorMessage } from '../../auth/formError';
import type { SecretState } from '../schema/schemaValues';
import styles from './ProfileForm.module.css';

export interface KeyPairPanelProps {
  protocol: string;
  /** The editing state of the private-key secret. */
  state: SecretState | undefined;
  /** The public key of the stored private key (`derived.publicKey`), when saved. */
  storedPublicKey: string | undefined;
  /** Takes a generated private key as a typed-in, unsaved secret. */
  onGenerated: (privateKey: string) => void;
}

function hasPrivateKey(state: SecretState | undefined): boolean {
  if (state === undefined || state.mode === 'remove') return false;
  return state.mode === 'stored' || state.value !== '';
}

/** The public key that belongs to the private key in the form; undefined when unknown. */
function shownPublicKey(
  state: SecretState | undefined,
  generated: KeyPair | undefined,
  storedPublicKey: string | undefined,
): string | undefined {
  if (state?.mode === 'stored') return storedPublicKey || undefined;
  if (generated && state && 'value' in state && state.value === generated.privateKey) {
    return generated.publicKey;
  }
  return undefined;
}

/**
 * "Generate key pair" below the private key: fills it in as a new value
 * (after a confirmation when one is set) and shows the matching public key
 * with Copy, for entering it on the server.
 */
export function KeyPairPanel({ protocol, state, storedPublicKey, onGenerated }: KeyPairPanelProps) {
  const { t } = useTranslation();
  const [generated, setGenerated] = useState<KeyPair>();
  const [confirming, setConfirming] = useState(false);
  const generate = useMutation({
    mutationFn: () => generateKeyPair(protocol),
    onSuccess: (pair) => {
      setGenerated(pair);
      onGenerated(pair.privateKey);
    },
  });
  const start = () => {
    setConfirming(false);
    generate.mutate();
  };
  const publicKey = shownPublicKey(state, generated, storedPublicKey);

  return (
    <div className={styles.keyPair}>
      {confirming ? (
        <div className={styles.confirm} role="group" aria-label={t('keyPair.confirmLabel')}>
          <span>{t('keyPair.confirmReplace')}</span>
          <div className={styles.buttons}>
            <Button onClick={() => setConfirming(false)}>{t('keyPair.cancel')}</Button>
            <Button variant="danger" onClick={start}>
              {t('keyPair.confirmButton')}
            </Button>
          </div>
        </div>
      ) : (
        <div className={styles.buttons}>
          <Button
            loading={generate.isPending}
            onClick={() => (hasPrivateKey(state) ? setConfirming(true) : start())}
          >
            {t('keyPair.generate')}
          </Button>
        </div>
      )}
      {generate.isError && (
        <Notice tone="danger" role="alert">
          {genericErrorMessage(t, generate.error)}
        </Notice>
      )}
      {publicKey && (
        <Field label={t('keyPair.publicKey')} hint={t('keyPair.publicKeyHint')}>
          {(control) => (
            <div className={styles.publicKey}>
              <input
                {...control}
                className={`${control.className ?? ''} ${styles.mono}`}
                value={publicKey}
                readOnly
              />
              <CopyButton text={publicKey} />
            </div>
          )}
        </Field>
      )}
    </div>
  );
}
