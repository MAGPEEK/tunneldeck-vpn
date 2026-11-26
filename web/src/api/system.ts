import { request } from './client';

export interface CheckResult {
  id: string;
  ok: boolean;
  /** A failed check that only turns a feature off; shown as a warning, not a failure. */
  warning?: boolean;
  /** Names the detail for translation as system.detail.<detailCode>; params fill its text. */
  detailCode?: string;
  params?: Record<string, string>;
  /** English detail; the fallback for an unknown detailCode. */
  detail: string;
  hint?: string;
}

export interface SystemInfo {
  version: string;
  listenAddress: string;
  /** RFC 3339 UTC. */
  serverTime: string;
  timeZone: string;
  checks: CheckResult[];
  /** Process start, RFC 3339 UTC. */
  startedAt?: string;
  /** How long the host has been running; missing when unknown. */
  hostUptimeSeconds?: number;
}

export function getSystem(): Promise<SystemInfo> {
  return request<SystemInfo>('/api/system');
}
