import { request } from './client';

export interface CheckResult {
  id: string;
  ok: boolean;
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
}

export function getSystem(): Promise<SystemInfo> {
  return request<SystemInfo>('/api/system');
}
