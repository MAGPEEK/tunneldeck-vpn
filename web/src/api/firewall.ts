import { request } from './client';

export type FirewallDirection = 'inbound' | 'outbound';
export type FirewallAction = 'accept' | 'drop' | 'reject';
export type FirewallProtocol = 'tcp' | 'udp' | 'tcp+udp' | 'icmp' | 'esp' | 'gre' | 'any';

/** A single port (`to` absent or equal to `from`) or the inclusive range from–to. */
export interface PortRange {
  from: number;
  to?: number;
}

/**
 * One rule as `internal/domain/firewall.go` serialises it. Absent ports mean "none".
 * `destination` is one IPv4 address in the local LAN for inbound rules and an
 * address or CIDR network for outbound rules.
 */
export interface FirewallRule {
  id: string;
  name: string;
  direction: FirewallDirection;
  action: FirewallAction;
  protocol: FirewallProtocol;
  icmpType?: string;
  source: string;
  sourcePort?: PortRange;
  destination: string;
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
  /** The address offered as "this device's address". */
  hostAddress: string;
  /** All of the host's LAN addresses: an inbound rule to one of them opens a service on the host. */
  hostAddresses: string[];
  lanSubnets: string[];
  ipForward: boolean;
  /** Hits per rule ID; null when the counters cannot be read. */
  counters: Record<string, RuleCounters> | null;
  countersAvailable: boolean;
  /** How far the host's kernel supports each global protection. */
  protectionsAvailable: ProtectionSupport;
}

/**
 * Support of a global protection: "full" as specified, "global" one shared rate
 * instead of one per sender, "none" left out because the kernel lacks the module.
 */
export type ProtectionLevel = 'full' | 'global' | 'none';

export interface ProtectionSupport {
  synFlood: ProtectionLevel;
  /** The ping limit is one global rate anyway, so it is never "global". */
  ping: Exclude<ProtectionLevel, 'global'>;
  mssClamp: Exclude<ProtectionLevel, 'global'>;
  ruleCounters: boolean;
}

/** Hits of one rule: packets counts the new connections it matched. */
export interface RuleCounters {
  packets: number;
  bytes: number;
}

/** One LAN neighbour of the host for the device picker. */
export interface LanDevice {
  address: string;
  mac: string;
  name?: string;
  state: string;
  onLan: boolean;
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

export async function getFirewallDevices(): Promise<LanDevice[]> {
  const response = await request<{ devices: LanDevice[] }>('/api/firewall/devices');
  return response.devices;
}

/** Rules of the "IPsec router" template; nothing is stored. */
export async function ipsecTemplate(body: IpsecTemplateRequest): Promise<FirewallRule[]> {
  const response = await request<{ rules: FirewallRule[] }>('/api/firewall/templates/ipsec', {
    method: 'POST',
    body,
  });
  return response.rules;
}

/** Whether an inbound rule to `destination` opens a service on the host instead of forwarding. */
export function targetsHost(destination: string, hostAddresses: readonly string[]): boolean {
  return hostAddresses.includes(destination.trim());
}

export function hasPorts(protocol: FirewallProtocol): boolean {
  return protocol === 'tcp' || protocol === 'udp' || protocol === 'tcp+udp';
}
