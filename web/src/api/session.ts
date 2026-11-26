import { request } from './client';

export interface Session {
  setupRequired: boolean;
  authenticated: boolean;
  username: string;
  /** "Stay signed in" is offered: only on the LAN HTTP listener, never over remote HTTPS. */
  rememberAvailable: boolean;
}

export interface Credentials {
  username: string;
  password: string;
}

export interface LoginRequest extends Credentials {
  /** Starts a "stay signed in" session; the server ignores it where it is not available. */
  remember?: boolean;
}

export function getSession(): Promise<Session> {
  return request<Session>('/api/session');
}

export function setup(credentials: Credentials): Promise<void> {
  return request<undefined>('/api/setup', { method: 'POST', body: credentials });
}

export function login(credentials: LoginRequest): Promise<void> {
  return request<undefined>('/api/login', { method: 'POST', body: credentials });
}

export function logout(): Promise<void> {
  return request<undefined>('/api/logout', { method: 'POST' });
}

/** Ends every session, this one included. */
export function logoutEverywhere(): Promise<void> {
  return request<undefined>('/api/sessions', { method: 'DELETE' });
}
