import type { RemoteAccess } from '../api/remoteAccess';
import { shownPublicIp } from '../publicIp/shownPublicIp';

/** Where the address of the remote access URL comes from. */
export type RemoteAccessSource = 'publicAddress' | 'detected' | 'vpnIp';

export interface RemoteAccessTarget {
  url: string;
  source: RemoteAccessSource;
}

/** Remote access is switched on and its HTTPS listener runs. */
export function remoteAccessActive(remote: RemoteAccess | null | undefined): boolean {
  return remote?.enabled === true && remote.listening;
}

/**
 * The URL of the web UI over remote access: the profile's public address,
 * else the detected public IP, else the tunnel's VPN IP; undefined while
 * none is known.
 */
export function remoteAccessTarget(
  port: number,
  publicAddress: string | undefined,
  detectedIp: string | undefined,
  vpnIp: string | undefined,
): RemoteAccessTarget | undefined {
  const shown = shownPublicIp(publicAddress, detectedIp);
  if (shown) {
    return {
      url: `https://${shown.address}:${port}`,
      source: shown.detected ? 'detected' : 'publicAddress',
    };
  }
  if (vpnIp) {
    return { url: `https://${vpnIp}:${port}`, source: 'vpnIp' };
  }
  return undefined;
}
