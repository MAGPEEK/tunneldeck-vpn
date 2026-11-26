import { request } from './client';

/** GET/PUT /api/public-ip-lookup (SPEC §6.1): detection of the tunnel's public IP. */
export interface PublicIpLookup {
  enabled: boolean;
  /** Absolute http(s) URL of a service that answers with the caller's IPv4 address as plain text. */
  url: string;
}

export function getPublicIpLookup(): Promise<PublicIpLookup> {
  return request<PublicIpLookup>('/api/public-ip-lookup');
}

export function putPublicIpLookup(body: PublicIpLookup): Promise<PublicIpLookup> {
  return request<PublicIpLookup>('/api/public-ip-lookup', { method: 'PUT', body });
}
