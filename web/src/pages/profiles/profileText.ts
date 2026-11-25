import type { TFunction } from 'i18next';
import type { Profile } from '../../api/profiles';
import { translateDynamic } from '../../i18n/dynamic';

/** Display name of a protocol ("OpenVPN"); unknown protocols show as sent. */
export function protocolName(t: TFunction, protocol: string): string {
  return translateDynamic(t, `protocols.${protocol}`, protocol);
}

/** "host:port" from the profile's remoteHost and port settings, or "" when unset. */
export function profileServer(profile: Pick<Profile, 'settings'>): string {
  const host = profile.settings.remoteHost;
  const port = profile.settings.port;
  if (typeof host !== 'string' || host === '') {
    return '';
  }
  const shownHost = host.includes(':') ? `[${host}]` : host;
  return typeof port === 'number' || typeof port === 'string' ? `${shownHost}:${port}` : shownHost;
}
