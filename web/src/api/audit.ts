import { request } from './client';

/** SPEC §8.2: what an audit log entry records. */
export type AuditType =
  | 'signedIn'
  | 'wrongCredentials'
  | 'signedOut'
  | 'signedOutEverywhere'
  | 'rateLimited'
  | 'remoteLocked'
  | 'remoteLockStarted'
  | 'remoteLockEnded'
  | 'csrfRejected'
  | 'bodyTooLarge'
  | 'invalidBody'
  | 'possibleScan';

/** Warnings are signs of an attack. */
export type AuditSeverity = 'info' | 'notice' | 'warning';

export interface AuditEntry {
  id: number;
  /** RFC 3339 UTC; for repeated events the latest. */
  time: string;
  /** RFC 3339 UTC; the first of repeated events, absent for a single one. */
  firstTime?: string;
  type: AuditType;
  severity: AuditSeverity;
  /** Empty for events without a client. */
  clientIp: string;
  access: 'lan' | 'remote';
  /** Sign-ins and sign-outs only. */
  username?: string;
  /** Number of repetitions counted in this entry. */
  count: number;
}

export interface AuditPage {
  /** Newest first. */
  entries: AuditEntry[];
  hasMore: boolean;
  /** Warning-level events of the last 24 hours, repetitions included. */
  recentWarnings: number;
  /** The latest sign-in, when it came over remote access from an address no earlier sign-in used. */
  newRemoteSignIn?: AuditEntry;
}

/** "" shows every entry. */
export type AuditFilter = '' | 'failures' | 'security';

export const AUDIT_PAGE_SIZE = 50;

export function getAudit(filter: AuditFilter, before?: number): Promise<AuditPage> {
  const params = new URLSearchParams({ limit: String(AUDIT_PAGE_SIZE) });
  if (before !== undefined) {
    params.set('before', String(before));
  }
  if (filter !== '') {
    params.set('filter', filter);
  }
  return request<AuditPage>(`/api/audit?${params.toString()}`);
}
