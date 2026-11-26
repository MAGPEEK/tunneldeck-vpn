import type { TFunction } from 'i18next';
import type { Profile, Settings } from '../../api/profiles';
import { translateDynamic } from '../../i18n/dynamic';

/** Display name of a protocol ("OpenVPN"); unknown protocols show as sent. */
export function protocolName(t: TFunction, protocol: string): string {
  return translateDynamic(t, `protocols.${protocol}`, protocol);
}

function nonEmpty(value: Settings[string] | undefined): string {
  return typeof value === 'string' ? value : '';
}

/**
 * "host:port" of the profile's server: a WireGuard `endpoint` as entered,
 * else the remoteHost and port settings; "" when unset.
 */
export function profileServer(profile: Pick<Profile, 'settings'>): string {
  const endpoint = nonEmpty(profile.settings.endpoint);
  if (endpoint !== '') {
    return endpoint;
  }
  const host = nonEmpty(profile.settings.remoteHost);
  const port = profile.settings.port;
  if (host === '') {
    return '';
  }
  const shownHost = host.includes(':') ? `[${host}]` : host;
  return typeof port === 'number' || typeof port === 'string' ? `${shownHost}:${port}` : shownHost;
}

/** The server's host name or address without port, from the endpoint or remoteHost; "" when unset. */
export function profileServerHost(settings: Settings): string {
  const endpoint = nonEmpty(settings.endpoint);
  return endpoint !== '' ? hostOfEndpoint(endpoint) : nonEmpty(settings.remoteHost);
}

/** "vpn.example.com:51820" → "vpn.example.com", "[2001:db8::1]:51820" → "2001:db8::1". */
function hostOfEndpoint(endpoint: string): string {
  const bracketed = /^\[([^\]]+)\](?::\d*)?$/.exec(endpoint);
  if (bracketed?.[1] !== undefined) {
    return bracketed[1];
  }
  const parts = endpoint.split(':');
  return parts.length === 2 ? (parts[0] ?? '') : endpoint;
}
