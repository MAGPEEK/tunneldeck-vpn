import { useTranslation } from 'react-i18next';
import { Card } from '../../../components/Card';
import { Field } from '../../../components/Field';
import styles from './ProfileForm.module.css';

export interface AccessSectionProps {
  publicAddress: string;
  error?: string;
  onChange: (publicAddress: string) => void;
}

/** Driver-independent access details of a connection: its public address. */
export function AccessSection({ publicAddress, error, onChange }: AccessSectionProps) {
  const { t } = useTranslation();
  return (
    <Card title={t('profileForm.access')}>
      <div className={styles.fields}>
        <Field
          label={t('profileForm.publicAddress')}
          value={publicAddress}
          hint={t('profileForm.publicAddressHint')}
          error={error}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
      </div>
    </Card>
  );
}
