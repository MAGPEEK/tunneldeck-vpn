import type { TFunction } from 'i18next';
import { hasPorts } from '../../api/firewall';
import type { RuleDraft } from './ruleDraft';

export function protocolText(t: TFunction, draft: RuleDraft): string {
  const name = t(`firewall.protocol.${draft.protocol}`);
  return draft.protocol === 'icmp' && draft.icmpType.trim() !== ''
    ? `${name} (${draft.icmpType.trim()})`
    : name;
}

/**
 * "203.0.113.0/24 :any → Host :5001" or "any :any → 192.168.2.2 :443 (public 4444)":
 * ports appear only for protocols that have them, "any" for an empty port,
 * the public port only when it differs from the destination port.
 */
export function routeText(t: TFunction, draft: RuleDraft): string {
  const any = t('firewall.any');
  const ports = hasPorts(draft.protocol);
  const withPort = (address: string, port: string) =>
    ports ? `${address} :${port.trim() || any}` : address;
  const toHost = draft.direction === 'inbound' && draft.destinationKind === 'host';
  const source = withPort(draft.source.trim() || any, draft.sourcePort);
  const destinationPort = draft.destinationPort.trim();
  const destination = withPort(
    toHost ? t('firewall.host') : draft.destinationCidr.trim() || any,
    destinationPort,
  );
  const publicPort = draft.publicPort.trim();
  const showPublic =
    ports &&
    !toHost &&
    draft.direction === 'inbound' &&
    destinationPort !== '' &&
    publicPort !== '' &&
    publicPort !== destinationPort;
  const suffix = showPublic ? ` ${t('firewall.publicPort', { port: publicPort })}` : '';
  return `${source} → ${destination}${suffix}`;
}

export function ruleName(t: TFunction, draft: RuleDraft): string {
  return draft.name.trim() || t('firewall.unnamed');
}
