import { useTranslation } from 'react-i18next';
import { durationText, parseTime } from '../../format/format';
import { useNow } from '../../hooks/useNow';

/** Time since `since`, updated every second. */
export function ConnectedSince({ since }: { since: string }) {
  const { t } = useTranslation();
  const start = parseTime(since);
  const now = useNow(1000, start !== undefined);
  if (start === undefined) {
    return <>–</>;
  }
  const { key, values } = durationText((now - start.getTime()) / 1000);
  return <time dateTime={since}>{t(key, values)}</time>;
}
