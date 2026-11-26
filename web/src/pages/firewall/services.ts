import type { FirewallProtocol } from '../../api/firewall';
import type { RuleDraft } from './ruleDraft';

/** The service presets of the step editor (SPEC §16.4). */
export type ServiceId = 'http' | 'https' | 'ssh' | 'rdp' | 'smb' | 'dns' | 'all' | 'custom';

interface PortPreset {
  protocol: FirewallProtocol;
  port: string;
}

const PORT_PRESETS: Record<Exclude<ServiceId, 'all' | 'custom'>, PortPreset> = {
  http: { protocol: 'tcp', port: '80' },
  https: { protocol: 'tcp', port: '443' },
  ssh: { protocol: 'tcp', port: '22' },
  rdp: { protocol: 'tcp', port: '3389' },
  smb: { protocol: 'tcp', port: '445' },
  dns: { protocol: 'tcp+udp', port: '53' },
};

export const SERVICE_IDS: ServiceId[] = [
  'http',
  'https',
  'ssh',
  'rdp',
  'smb',
  'dns',
  'all',
  'custom',
];

/**
 * The protocol of "All ports": every protocol where the model allows it
 * (outbound rules and blocks), otherwise TCP+UDP, since an inbound allow
 * of every protocol is refused.
 */
export function allPortsProtocol(draft: Pick<RuleDraft, 'direction' | 'action'>): FirewallProtocol {
  return draft.direction === 'outbound' || draft.action !== 'accept' ? 'any' : 'tcp+udp';
}

/** The preset a draft matches; anything else is "custom". */
export function detectService(draft: RuleDraft): ServiceId {
  const port = draft.destinationPort.trim();
  const protocol = draft.protocol;
  if (protocol === 'any' || (protocol === allPortsProtocol(draft) && port === '')) {
    return 'all';
  }
  const preset = (Object.keys(PORT_PRESETS) as (keyof typeof PORT_PRESETS)[]).find(
    (id) => PORT_PRESETS[id].protocol === protocol && PORT_PRESETS[id].port === port,
  );
  return preset ?? 'custom';
}

/** The draft fields a preset sets; "custom" keeps what is there. */
export function serviceChange(id: ServiceId, draft: RuleDraft): Partial<RuleDraft> {
  if (id === 'custom') {
    return {};
  }
  if (id === 'all') {
    return { protocol: allPortsProtocol(draft), destinationPort: '', publicPort: '' };
  }
  const preset = PORT_PRESETS[id];
  return { protocol: preset.protocol, destinationPort: preset.port, publicPort: '' };
}

/** "443/tcp" style detail shown next to a preset's name. */
export function presetDetail(id: ServiceId): string | undefined {
  if (id === 'all' || id === 'custom') {
    return undefined;
  }
  const preset = PORT_PRESETS[id];
  return `${preset.port}/${preset.protocol}`;
}
