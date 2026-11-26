import { request } from './client';
import type { Advisory, Protocol } from './profiles';

export type ConnectionState =
  'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'disconnecting' | 'error';

export interface StatusError {
  code: string;
  message: string;
  time: string;
}

/** GET /api/connection. Rates are bytes per second; times are RFC 3339 UTC. */
export interface ConnectionStatus {
  state: ConnectionState;
  message?: string;
  profileId?: string;
  profileName?: string;
  protocol?: Protocol;
  vpnIp?: string;
  remote?: string;
  since: string;
  bytesIn: number;
  bytesOut: number;
  rateIn: number;
  rateOut: number;
  lastError?: StatusError;
  advisories: Advisory[];
  /** Negotiated data channel cipher, e.g. "CHACHA20-POLY1305"; "none" when unencrypted. */
  dataCipher?: string;
  /** Control channel TLS version and cipher suite, e.g. "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256". */
  controlChannel?: string;
  /** Set while a connected tunnel runs without the routing of forwarded traffic; retried. */
  routingWarning?: StatusError;
  /** Public IPv4 address the internet sees through the connected tunnel, when detected. */
  publicIp?: string;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogLine {
  time: string;
  level: LogLevel;
  text: string;
}

/** Data of the SSE "state" event. */
export interface StateEvent {
  state: ConnectionState;
  code?: string;
  message?: string;
  vpnIp?: string;
  remote?: string;
  since: string;
}

/** Data of the SSE "traffic" event. */
export interface TrafficEvent {
  bytesIn: number;
  bytesOut: number;
  rateIn: number;
  rateOut: number;
}

/** Data of the SSE "channel" event; a missing field leaves the known value unchanged. */
export interface ChannelEvent {
  dataCipher?: string;
  controlChannel?: string;
}

/** Data of the SSE "publicIp" event; an empty publicIp means unknown. */
export interface PublicIpEvent {
  publicIp: string;
}

/** The ring buffer on the server holds this many lines; the UI keeps the same. */
export const LOG_CAPACITY = 2000;

export function getConnection(): Promise<ConnectionStatus> {
  return request<ConnectionStatus>('/api/connection');
}

export function connect(profileId: string): Promise<ConnectionStatus> {
  return request<ConnectionStatus>('/api/connection/connect', {
    method: 'POST',
    body: { profileId },
  });
}

export function disconnect(): Promise<ConnectionStatus> {
  return request<ConnectionStatus>('/api/connection/disconnect', { method: 'POST' });
}

export function reconnect(): Promise<ConnectionStatus> {
  return request<ConnectionStatus>('/api/connection/reconnect', { method: 'POST' });
}

export async function getLogs(tail = LOG_CAPACITY): Promise<LogLine[]> {
  const response = await request<{ lines: LogLine[] }>(`/api/logs?tail=${tail}`);
  return response.lines;
}
