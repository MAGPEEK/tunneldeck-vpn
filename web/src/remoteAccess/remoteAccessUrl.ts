import type { RemoteAccess } from '../api/remoteAccess';

export interface RemoteAccessTarget {
  url: string;
  /** True when the URL uses the tunnel's VPN IP because the profile names no public address. */
  fromVpnIp: boolean;
}

/** Remote access is switched on and its HTTPS listener runs. */
export function remoteAccessActive(remote: RemoteAccess | null | undefined): boolean {
  return remote?.enabled === true && remote.listening;
}

/**
 * The URL of the web UI over remote access: the profile's public address,
 * else the tunnel's VPN IP; undefined while neither is known.
 */
export function remoteAccessTarget(
  port: number,
  publicAddress: string | undefined,
  vpnIp: string | undefined,
): RemoteAccessTarget | undefined {
  const address = publicAddress?.trim();
  if (address) {
    return { url: `https://${address}:${port}`, fromVpnIp: false };
  }
  if (vpnIp) {
    return { url: `https://${vpnIp}:${port}`, fromVpnIp: true };
  }
  return undefined;
}
