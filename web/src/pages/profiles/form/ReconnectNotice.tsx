import { useTranslation } from 'react-i18next';
import { Button } from '../../../components/Button';
import { useConnection, useConnectionControl } from '../../../queries/queries';

const LIVE_STATES = new Set(['connecting', 'connected', 'reconnecting']);

/** "Changes apply on the next connect." with Reconnect now, while this profile is up. */
export function ReconnectNotice({ profileId }: { profileId: string }) {
  const { t } = useTranslation();
  const connection = useConnection();
  const { reconnect } = useConnectionControl();
  const status = connection.data;
  if (!status || status.profileId !== profileId || !LIVE_STATES.has(status.state)) {
    return null;
  }
  return (
    <>
      <p>{t('profileForm.appliesOnNextConnect')}</p>
      <div>
        <Button loading={reconnect.isPending} onClick={() => reconnect.mutate()}>
          {t('profileForm.reconnectNow')}
        </Button>
      </div>
      {reconnect.isError && <p role="alert">{t('errors.unexpected')}</p>}
    </>
  );
}
