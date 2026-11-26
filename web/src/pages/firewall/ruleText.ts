import type { TFunction } from 'i18next';
import { hasPorts, type LanDevice } from '../../api/firewall';
import { EVERYWHERE, isPortForward, type RuleDraft } from './ruleDraft';
import { detectService, type ServiceId } from './services';

/** What the texts of a rule depend on besides the rule itself. */
export interface RuleContext {
  hostAddresses: readonly string[];
  devices: readonly LanDevice[];
}

export function ruleName(t: TFunction, draft: RuleDraft): string {
  return draft.name.trim() || t('firewall.unnamed');
}

export function protocolText(t: TFunction, draft: RuleDraft): string {
  const name = t(`firewall.protocol.${draft.protocol}`);
  return draft.protocol === 'icmp' && draft.icmpType.trim() !== ''
    ? `${name} (${draft.icmpType.trim()})`
    : name;
}

/** The picker's name of a LAN address, if it has one. */
export function deviceNameOf(address: string, devices: readonly LanDevice[]): string | undefined {
  const name = devices.find((device) => device.address === address.trim())?.name;
  return name === undefined || name === '' ? undefined : name;
}

/** "This device", a device's name, or the address itself; "not set" when empty. */
export function deviceLabel(t: TFunction, address: string, context: RuleContext): string {
  const trimmed = address.trim();
  if (trimmed === '') {
    return t('firewall.flow.unset');
  }
  if (context.hostAddresses.includes(trimmed)) {
    return t('firewall.flow.thisDevice');
  }
  return deviceNameOf(trimmed, context.devices) ?? trimmed;
}

/** One chip of the flow strip: the zone and what in it the rule is about. */
export interface FlowEndpoint {
  zone: 'vpn' | 'lan';
  label: string;
  /** The LAN device the rule is about, shown in the accent colour. */
  accent: boolean;
}

/** `VPN · sender → Local LAN · device` inbound, `Local LAN · device → VPN · destination` outbound. */
export function flowEndpoints(
  t: TFunction,
  draft: RuleDraft,
  context: RuleContext,
): [FlowEndpoint, FlowEndpoint] {
  const any = t('firewall.any');
  if (draft.direction === 'inbound') {
    return [
      { zone: 'vpn', label: draft.source.trim() || any, accent: false },
      { zone: 'lan', label: deviceLabel(t, draft.destination, context), accent: true },
    ];
  }
  const destination = draft.destination.trim();
  return [
    { zone: 'lan', label: deviceLabel(t, draft.source, context), accent: true },
    {
      zone: 'vpn',
      label: destination === '' || destination === EVERYWHERE ? any : destination,
      accent: false,
    },
  ];
}

const NAMED_SERVICES: ServiceId[] = ['http', 'https', 'ssh', 'rdp', 'smb', 'dns'];

/** The service in plain words: "HTTPS (TCP 443)", "all ports", "TCP 8000-8010", "ESP". */
export function serviceText(t: TFunction, draft: RuleDraft): string {
  const service = detectService(draft);
  if (service === 'all') {
    return t('firewall.line.allPorts');
  }
  const protocol = protocolText(t, draft);
  const port = draft.destinationPort.trim();
  const ports = hasPorts(draft.protocol) ? `${protocol} ${port || t('firewall.any')}` : protocol;
  return NAMED_SERVICES.includes(service)
    ? `${t(`firewall.service.${service}`)} (${ports})`
    : ports;
}

/** The name step's suggestion: "<device> <service>", at most 64 characters. */
export function suggestedName(
  t: TFunction,
  draft: RuleDraft,
  service: ServiceId,
  context: RuleContext,
): string {
  const address = draft.direction === 'inbound' ? draft.destination : draft.source;
  const device = address.trim() === '' ? '' : deviceLabel(t, address, context);
  const what = service === 'custom' ? serviceText(t, draft) : t(`firewall.service.${service}`);
  return [device, what].filter(Boolean).join(' ').slice(0, 64);
}

/** The second line of a list row: name · service · notable options. */
export function ruleLine(t: TFunction, draft: RuleDraft, context: RuleContext): string {
  const parts = [ruleName(t, draft), serviceText(t, draft)];
  const forward = isPortForward(draft, context.hostAddresses);
  if (!forward && draft.action !== 'accept') {
    parts.push(t(`firewall.action.${draft.action}`));
  }
  const destinationPort = draft.destinationPort.trim();
  const publicPort = draft.publicPort.trim();
  const otherVpnPort =
    hasPorts(draft.protocol) &&
    destinationPort !== '' &&
    publicPort !== '' &&
    publicPort !== destinationPort;
  if (forward && otherVpnPort) {
    parts.push(t('firewall.line.vpnPort', { port: publicPort }));
  }
  if (forward && draft.keepSourceAddress) {
    parts.push(t('firewall.line.senderKept'));
  }
  if (!draft.enabled) {
    parts.push(t('firewall.line.off'));
  }
  return parts.join(' · ');
}
