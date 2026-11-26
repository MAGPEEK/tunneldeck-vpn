import type { TFunction } from 'i18next';
import { hasPorts } from '../../api/firewall';
import { EVERYWHERE, isPortForward, type RuleDraft } from './ruleDraft';
import { deviceNameOf, protocolText, type RuleContext } from './ruleText';

/**
 * The plain-language texts of the step editor, generated from the same
 * draft the rule is saved from: `ruleSummary` says what happens,
 * `ruleCreates` lists the technical entries the rule installs.
 */

function senderText(t: TFunction, draft: RuleDraft): string {
  const source = draft.source.trim();
  const sender = source === '' ? t('firewall.summary.anySender') : source;
  const port = draft.sourcePort.trim();
  return port !== '' && hasPorts(draft.protocol)
    ? t('firewall.summary.senderPort', { sender, port })
    : sender;
}

/** " on TCP port 443", " on every TCP+UDP port", " via ESP"; "" for any protocol. */
function servicePhrase(t: TFunction, draft: RuleDraft, port: string): string {
  const protocol = protocolText(t, draft);
  if (hasPorts(draft.protocol)) {
    if (port === '') return t('firewall.summary.everyPort', { protocol });
    const key = port.includes('-') ? 'firewall.summary.onPorts' : 'firewall.summary.onPort';
    return t(key, { protocol, port });
  }
  return draft.protocol === 'any' ? '' : t('firewall.summary.via', { protocol });
}

/** "this device (192.168.1.10)", "Web server (192.168.1.20)" or the address. */
function targetText(t: TFunction, address: string, context: RuleContext): string {
  const trimmed = address.trim();
  if (trimmed === '') return t('firewall.summary.noDevice');
  if (context.hostAddresses.includes(trimmed)) {
    return t('firewall.summary.thisDevice', { address: trimmed });
  }
  const name = deviceNameOf(trimmed, context.devices);
  return name === undefined ? trimmed : t('firewall.summary.named', { name, address: trimmed });
}

function remoteText(t: TFunction, draft: RuleDraft): string {
  const destination = draft.destination.trim();
  return destination === '' || destination === EVERYWHERE
    ? t('firewall.summary.anyAddress')
    : destination;
}

function publicPortOf(draft: RuleDraft): string {
  const destinationPort = draft.destinationPort.trim();
  return destinationPort === '' ? '' : draft.publicPort.trim() || destinationPort;
}

function inboundSummary(t: TFunction, draft: RuleDraft, context: RuleContext): string[] {
  const sender = senderText(t, draft);
  const target = targetText(t, draft.destination, context);
  const service = servicePhrase(t, draft, draft.destinationPort.trim());
  if (!isPortForward(draft, context.hostAddresses)) {
    return [t(`firewall.summary.host_${draft.action}`, { sender, target, service })];
  }
  const device = deviceNameOf(draft.destination, context.devices) ?? draft.destination.trim();
  const publicService = servicePhrase(t, draft, publicPortOf(draft));
  return [
    t('firewall.summary.forward', { sender, publicService, target, service }),
    t(draft.keepSourceAddress ? 'firewall.summary.keepSender' : 'firewall.summary.masquerade', {
      device,
    }),
  ];
}

function outboundSummary(t: TFunction, draft: RuleDraft, context: RuleContext): string[] {
  const values = {
    device: targetText(t, draft.source, context),
    destination: remoteText(t, draft),
    service: servicePhrase(t, draft, draft.destinationPort.trim()),
  };
  const sentence = t(`firewall.summary.outbound_${draft.action}`, values);
  return draft.action === 'accept' ? [sentence, t('firewall.summary.killSwitch')] : [sentence];
}

export function ruleSummary(t: TFunction, draft: RuleDraft, context: RuleContext): string[] {
  const sentences =
    draft.direction === 'inbound'
      ? inboundSummary(t, draft, context)
      : outboundSummary(t, draft, context);
  return draft.enabled ? sentences : [...sentences, t('firewall.summary.off')];
}

/** "TCP 443", "TCP+UDP any port", "ESP", "any protocol". */
function compactService(t: TFunction, draft: RuleDraft, port: string): string {
  if (draft.protocol === 'any') return t('firewall.creates.anyProtocol');
  const protocol = protocolText(t, draft);
  if (!hasPorts(draft.protocol)) return protocol;
  return port === '' ? t('firewall.creates.anyPort', { protocol }) : `${protocol} ${port}`;
}

/** The values of a filter line: what is allowed, from whom, to where. */
type FilterValues = {
  action: string;
  service: string;
  sender: string;
  address: string;
};

function forwardCreates(t: TFunction, draft: RuleDraft, values: FilterValues): string[] {
  const address = draft.destination.trim();
  const port = draft.destinationPort.trim();
  const target = hasPorts(draft.protocol) && port !== '' ? `${address}:${port}` : address;
  const entries = [
    t('firewall.creates.filterForward', values),
    t('firewall.creates.dnat', {
      service: compactService(t, draft, publicPortOf(draft)),
      target,
    }),
  ];
  if (!draft.keepSourceAddress) {
    entries.push(t('firewall.creates.masqueradeLan', { address }));
  }
  entries.push(t('firewall.creates.replyRoute', { address }));
  return entries;
}

export function ruleCreates(t: TFunction, draft: RuleDraft, context: RuleContext): string[] {
  if (!draft.enabled) {
    return [t('firewall.creates.nothing')];
  }
  const outbound = draft.direction === 'outbound';
  const values: FilterValues = {
    action: t(`firewall.creates.action.${draft.action}`),
    service: compactService(t, draft, draft.destinationPort.trim()),
    sender: outbound ? draft.source.trim() : senderText(t, draft),
    address: outbound ? remoteText(t, draft) : draft.destination.trim(),
  };
  if (!outbound) {
    return isPortForward(draft, context.hostAddresses)
      ? forwardCreates(t, draft, values)
      : [t('firewall.creates.filterInput', values)];
  }
  if (draft.action !== 'accept') {
    return [t('firewall.creates.filterForward', values)];
  }
  return [
    t('firewall.creates.policyRoute', { source: values.sender, destination: values.address }),
    t('firewall.creates.filterForward', values),
    t('firewall.creates.masqueradeVpn'),
  ];
}
