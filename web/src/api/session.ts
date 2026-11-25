import { request } from './client';

export interface Session {
  setupRequired: boolean;
  authenticated: boolean;
  username: string;
}

export interface Credentials {
  username: string;
  password: string;
}

export function getSession(): Promise<Session> {
  return request<Session>('/api/session');
}

export function setup(credentials: Credentials): Promise<void> {
  return request<undefined>('/api/setup', { method: 'POST', body: credentials });
}

export function login(credentials: Credentials): Promise<void> {
  return request<undefined>('/api/login', { method: 'POST', body: credentials });
}

export function logout(): Promise<void> {
  return request<undefined>('/api/logout', { method: 'POST' });
}
