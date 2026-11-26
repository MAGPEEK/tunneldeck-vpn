/** The public address shown for the tunnel and where it comes from. */
export interface ShownPublicIp {
  address: string;
  /** True when TunnelDeck-VPN detected it because the profile names no public address. */
  detected: boolean;
}

/**
 * The public address of the tunnel: the profile's public address, which
 * always wins, else the detected public IP; undefined while neither is known.
 */
export function shownPublicIp(
  publicAddress: string | undefined,
  detectedIp: string | undefined,
): ShownPublicIp | undefined {
  const address = publicAddress?.trim();
  if (address) {
    return { address, detected: false };
  }
  if (detectedIp) {
    return { address: detectedIp, detected: true };
  }
  return undefined;
}
