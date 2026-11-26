import type { ConnectionState, ConnectionStatus } from '../../api/connection';
import { targetsHost, type FirewallRule, type FirewallState } from '../../api/firewall';
import type { StateTone } from '../../components/StatePill';

/** Colour of a link in the connection line; dashed means "no link". */
export interface LineStyle {
  tone: StateTone;
  dashed: boolean;
}

export const STATE_TONES: Record<ConnectionState, StateTone> = {
  disconnected: 'neutral',
  connecting: 'warning',
  reconnecting: 'warning',
  disconnecting: 'warning',
  connected: 'success',
  error: 'danger',
};

/** Below this width (px) the connection line stacks vertically. */
export const NARROW_QUERY = '(max-width: 719.98px)';

export type LineLayout = 'horizontal' | 'vertical';

export function lineLayout(narrow: boolean): LineLayout {
  return narrow ? 'vertical' : 'horizontal';
}

/** The tunnel link between VPN and this device: dashed while disconnected. */
export function tunnelLine(state: ConnectionState): LineStyle {
  return { tone: STATE_TONES[state], dashed: state === 'disconnected' };
}

/** Whether the tunnel carries traffic, so rates, totals and the VPN address mean something. */
export function tunnelUp(state: ConnectionState): boolean {
  return state === 'connected' || state === 'reconnecting';
}

/** An enabled inbound rule to a LAN device other than this host: a port forward. */
function isForward(rule: FirewallRule, hostAddresses: readonly string[]): boolean {
  return (
    rule.enabled && rule.direction === 'inbound' && !targetsHost(rule.destination, hostAddresses)
  );
}

export function activeRules(firewall: FirewallState): number {
  return firewall.rules.filter((rule) => rule.enabled).length;
}

export function activeForwards(firewall: FirewallState): number {
  return firewall.rules.filter((rule) => isForward(rule, firewall.hostAddresses)).length;
}

/** Whether an enabled rule needs IP forwarding: a port forward or an outbound rule. */
export function needsForwarding(firewall: FirewallState): boolean {
  return firewall.rules.some(
    (rule) =>
      isForward(rule, firewall.hostAddresses) || (rule.enabled && rule.direction === 'outbound'),
  );
}

/** Whether forward rules exist although the host does not forward packets. */
export function forwardingBlocked(firewall: FirewallState): boolean {
  return !firewall.ipForward && needsForwarding(firewall);
}

/** Whether a switched-on protection runs reduced or not at all on this kernel. */
export function protectionsDegraded(firewall: FirewallState): boolean {
  const { settings, protectionsAvailable: available } = firewall;
  return (
    (settings.synFloodProtection && available.synFlood !== 'full') ||
    (settings.pingLimit && available.ping === 'none') ||
    (settings.mssClamp && available.mssClamp === 'none')
  );
}

/** The firewall link between this device and the LAN. */
export function firewallLine(
  firewall: FirewallState | undefined,
  status: ConnectionStatus,
): LineStyle {
  if (status.state === 'error' && status.lastError?.code === 'firewall_failed') {
    return { tone: 'danger', dashed: false };
  }
  if (firewall === undefined) {
    return { tone: 'neutral', dashed: true };
  }
  if (protectionsDegraded(firewall) || forwardingBlocked(firewall)) {
    return { tone: 'warning', dashed: false };
  }
  return { tone: 'success', dashed: false };
}
