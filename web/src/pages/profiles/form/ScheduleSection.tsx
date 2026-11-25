import { useTranslation } from 'react-i18next';
import type { DailyReconnect } from '../../../api/profiles';
import { Card } from '../../../components/Card';
import { Field } from '../../../components/Field';
import { CheckboxField } from '../schema/CheckboxField';
import styles from './ProfileForm.module.css';

export interface ScheduleSectionProps {
  value: DailyReconnect;
  timeZone: string | undefined;
  error?: string;
  onChange: (value: DailyReconnect) => void;
}

export function ScheduleSection({ value, timeZone, error, onChange }: ScheduleSectionProps) {
  const { t } = useTranslation();
  return (
    <Card title={t('profileForm.schedule')}>
      <div className={styles.fields}>
        <CheckboxField
          label={t('profileForm.dailyReconnect')}
          checked={value.enabled}
          onChange={(enabled) => onChange({ ...value, enabled })}
        />
        <Field
          label={t('profileForm.dailyReconnectTime')}
          type="time"
          className={styles.timeField}
          value={value.time}
          disabled={!value.enabled}
          hint={timeZone ? t('profileForm.timeZoneHint', { timeZone }) : undefined}
          error={error}
          onChange={(event) => onChange({ ...value, time: event.currentTarget.value })}
        />
      </div>
    </Card>
  );
}
