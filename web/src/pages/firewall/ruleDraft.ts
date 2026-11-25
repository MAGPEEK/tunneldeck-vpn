import {
  hasPorts,
  type DestinationKind,
  type FirewallAction,
  type FirewallDirection,
  type FirewallProtocol,
  type FirewallRule,
  type PortRange,
} from '../../api/firewall';

/** A rule while it is edited: ports stay text ("443", "8000-8010") until saved. */
export interface RuleDraft {
  key: string;
  id: string;
  name: string;
  direction: FirewallDirection;
  action: FirewallAction;
  protocol: FirewallProtocol;
  icmpType: string;
  source: string;
  sourcePort: string;
  destinationKind: DestinationKind;
  destinationCidr: string;
  destinationPort: string;
  publicPort: string;
  keepSourceAddress: boolean;
  enabled: boolean;
  comment: string;
  /** Inserted by a template and not saved yet. */
  highlighted: boolean;
}

export type PortField = 'sourcePort' | 'destinationPort' | 'publicPort';

let nextKey = 0;

function draftKey(): string {
  nextKey += 1;
  return `rule-${nextKey}`;
}

export function formatPort(port: PortRange | undefined): string {
  if (port === undefined || (port.from === 0 && !port.to)) {
    return '';
  }
  return port.to === undefined || port.to === port.from
    ? String(port.from)
    : `${port.from}-${port.to}`;
}

const PORT_PATTERN = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/;

/** Parses "443" or "8000-8010"; "" is no port; anything else is `null`. */
export function parsePort(text: string): PortRange | undefined | null {
  const trimmed = text.trim();
  if (trimmed === '') {
    return undefined;
  }
  const match = PORT_PATTERN.exec(trimmed);
  if (!match) {
    return null;
  }
  const from = Number(match[1]);
  const to = match[2] === undefined ? undefined : Number(match[2]);
  return to === undefined || to === from ? { from } : { from, to };
}

export function toDraft(rule: FirewallRule, highlighted = false): RuleDraft {
  return {
    key: draftKey(),
    id: rule.id,
    name: rule.name,
    direction: rule.direction,
    action: rule.action || 'accept',
    protocol: rule.protocol,
    icmpType: rule.icmpType ?? '',
    source: rule.source,
    sourcePort: formatPort(rule.sourcePort),
    destinationKind: rule.destination.kind,
    destinationCidr: rule.destination.cidr ?? '',
    destinationPort: formatPort(rule.destinationPort),
    publicPort: formatPort(rule.publicPort),
    keepSourceAddress: rule.keepSourceAddress,
    enabled: rule.enabled,
    comment: rule.comment,
    highlighted,
  };
}

export function newDraft(direction: FirewallDirection): RuleDraft {
  return {
    key: draftKey(),
    id: '',
    name: '',
    direction,
    action: 'accept',
    protocol: direction === 'inbound' ? 'tcp+udp' : 'any',
    icmpType: '',
    source: '',
    sourcePort: '',
    destinationKind: direction === 'inbound' ? 'host' : 'address',
    destinationCidr: '',
    destinationPort: '',
    publicPort: '',
    keepSourceAddress: false,
    enabled: true,
    comment: '',
    highlighted: false,
  };
}

export function duplicateDraft(draft: RuleDraft, name: string): RuleDraft {
  return { ...draft, key: draftKey(), id: '', name, highlighted: false };
}

/** Whether the rule forwards inbound traffic to another LAN device. */
export function isPortForward(draft: RuleDraft): boolean {
  return draft.direction === 'inbound' && draft.destinationKind === 'address';
}

/** The port fields the editor shows for the draft's protocol, direction and destination. */
export function visiblePortFields(draft: RuleDraft): PortField[] {
  if (!hasPorts(draft.protocol)) {
    return [];
  }
  return draft.direction === 'inbound'
    ? ['sourcePort', 'destinationPort', 'publicPort']
    : ['sourcePort', 'destinationPort'];
}

/** Port fields whose text is neither empty, a port nor a range. */
export function invalidPortFields(draft: RuleDraft): PortField[] {
  return visiblePortFields(draft).filter((field) => parsePort(draft[field]) === null);
}

function port(text: string): PortRange | undefined {
  return parsePort(text) ?? undefined;
}

/**
 * The rule as the API takes it. Fields that do not apply to the protocol,
 * direction or destination are dropped, so switching back and forth in the
 * editor loses nothing until the rule is saved.
 */
export function toRule(draft: RuleDraft): FirewallRule {
  const forward = isPortForward(draft);
  const toHost = draft.direction === 'inbound' && draft.destinationKind === 'host';
  const rule: FirewallRule = {
    id: draft.id,
    name: draft.name.trim(),
    direction: draft.direction,
    action: forward ? 'accept' : draft.action,
    protocol: draft.protocol,
    source: draft.source.trim(),
    destination: toHost
      ? { kind: 'host' }
      : { kind: 'address', cidr: draft.destinationCidr.trim() },
    keepSourceAddress: forward && draft.keepSourceAddress,
    enabled: draft.enabled,
    comment: draft.comment.trim(),
  };
  if (draft.protocol === 'icmp' && draft.icmpType.trim() !== '') {
    rule.icmpType = draft.icmpType.trim();
  }
  if (hasPorts(draft.protocol)) {
    const sourcePort = port(draft.sourcePort);
    const destinationPort = port(draft.destinationPort);
    const publicPort =
      draft.direction === 'inbound' && !toHost ? port(draft.publicPort) : undefined;
    if (sourcePort) rule.sourcePort = sourcePort;
    if (destinationPort) rule.destinationPort = destinationPort;
    if (publicPort) rule.publicPort = publicPort;
  }
  return rule;
}

export function draftsDiffer(
  drafts: readonly RuleDraft[],
  saved: readonly FirewallRule[],
): boolean {
  return (
    JSON.stringify(drafts.map(toRule)) !==
    JSON.stringify(saved.map((rule) => toRule(toDraft(rule))))
  );
}

/** Moves the draft `key` one place up or down among the drafts of its direction. */
export function moveDraft(drafts: readonly RuleDraft[], key: string, step: -1 | 1): RuleDraft[] {
  const index = drafts.findIndex((draft) => draft.key === key);
  const moving = drafts[index];
  if (moving === undefined) {
    return [...drafts];
  }
  let target = index + step;
  while (target >= 0 && target < drafts.length && drafts[target]?.direction !== moving.direction) {
    target += step;
  }
  const other = drafts[target];
  if (other === undefined) {
    return [...drafts];
  }
  const next = [...drafts];
  next[target] = moving;
  next[index] = other;
  return next;
}

/** Field errors per draft key from API keys such as `rules[2].destination`. */
export function errorsByDraft(
  fields: Record<string, string>,
  sent: readonly RuleDraft[],
): Record<string, Record<string, string>> {
  const result: Record<string, Record<string, string>> = {};
  for (const [path, message] of Object.entries(fields)) {
    const match = /^rules\[(\d+)\]\.(.+)$/.exec(path);
    const draft = match ? sent[Number(match[1])] : undefined;
    if (match?.[2] === undefined || draft === undefined) {
      continue;
    }
    result[draft.key] = { ...result[draft.key], [match[2]]: message };
  }
  return result;
}
