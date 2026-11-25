import type { TFunction } from 'i18next';
import { hasPorts } from '../../api/firewall';
import type { RuleDraft } from './ruleDraft';

export function protocolText(t: TFunction, draft: RuleDraft): string {
  const name = t(`firewall.protocol.${draft.protocol}`);
  return draft.protocol === 'icmp' && draft.icmpType.trim() !== ''
    ? `${name} (${draft.icmpType.trim()})`
    : name;
}

function withPort(address: string, port: string): string {
  return port.trim() === '' ? address : `${address} :${port.trim()}`;
}

/**
 * "203.0.113.0/24 → This device :5001" or "any → 192.168.2.2 :443 (public 4444)":
 * ports appear only for protocols that have them, the public port only when
 * it differs from the destination port.
 */
export function routeText(t: TFunction, draft: RuleDraft): string {
  const ports = hasPorts(draft.protocol);
  const source = withPort(draft.source.trim() || t('firewall.any'), ports ? draft.sourcePort : '');
  const toHost = draft.direction === 'inbound' && draft.destinationKind === 'host';
  const destination = withPort(
    toHost ? t('firewall.thisDevice') : draft.destinationCidr.trim() || t('firewall.any'),
    ports ? draft.destinationPort : '',
  );
  const publicPort = draft.publicPort.trim();
  const showPublic =
    ports &&
    !toHost &&
    draft.direction === 'inbound' &&
    publicPort !== '' &&
    publicPort !== draft.destinationPort.trim();
  const suffix = showPublic ? ` ${t('firewall.publicPort', { port: publicPort })}` : '';
  return `${source} → ${destination}${suffix}`;
}

export function ruleName(t: TFunction, draft: RuleDraft): string {
  return draft.name.trim() || t('firewall.unnamed');
}
