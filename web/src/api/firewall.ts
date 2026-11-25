import { request } from './client';

export type FirewallDirection = 'inbound' | 'outbound';
export type FirewallAction = 'accept' | 'drop' | 'reject';
export type FirewallProtocol = 'tcp' | 'udp' | 'tcp+udp' | 'icmp' | 'esp' | 'gre' | 'any';
export type DestinationKind = 'host' | 'address';

/** A single port (`to` absent or equal to `from`) or the inclusive range from–to. */
export interface PortRange {
  from: number;
  to?: number;
}

export interface FirewallDestination {
  kind: DestinationKind;
  cidr?: string;
}

/** One rule as `internal/domain/firewall.go` serialises it. Absent ports mean "none". */
export interface FirewallRule {
  id: string;
  name: string;
  direction: FirewallDirection;
  action: FirewallAction;
  protocol: FirewallProtocol;
  icmpType?: string;
  source: string;
  sourcePort?: PortRange;
  destination: FirewallDestination;
  destinationPort?: PortRange;
  publicPort?: PortRange;
  keepSourceAddress: boolean;
  enabled: boolean;
  comment: string;
}

export interface FirewallSettings {
  dropInvalid: boolean;
  mssClamp: boolean;
  synFloodProtection: boolean;
  pingLimit: boolean;
}

/** GET/PUT answer: the stored firewall plus the detected host network (empty when unknown). */
export interface FirewallState {
  rules: FirewallRule[];
  settings: FirewallSettings;
  hostAddress: string;
  lanSubnets: string[];
  ipForward: boolean;
}

export interface FirewallUpdate {
  rules: FirewallRule[];
  settings: FirewallSettings;
}

export interface IpsecTemplateRequest {
  name: string;
  deviceAddress: string;
  peers: string[];
}

export function getFirewall(): Promise<FirewallState> {
  return request<FirewallState>('/api/firewall');
}

export function putFirewall(update: FirewallUpdate): Promise<FirewallState> {
  return request<FirewallState>('/api/firewall', { method: 'PUT', body: update });
}

/** Rules of the "IPsec device" template; nothing is stored. */
export async function ipsecTemplate(body: IpsecTemplateRequest): Promise<FirewallRule[]> {
  const response = await request<{ rules: FirewallRule[] }>('/api/firewall/templates/ipsec', {
    method: 'POST',
    body,
  });
  return response.rules;
}

export function hasPorts(protocol: FirewallProtocol): boolean {
  return protocol === 'tcp' || protocol === 'udp' || protocol === 'tcp+udp';
}
