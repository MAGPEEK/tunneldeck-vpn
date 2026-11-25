import { request } from './client';

export type Transport = 'tcp' | 'udp';

export interface HostAccessRule {
  id: string;
  protocol: Transport;
  port: number;
  sourceCidr: string;
  enabled: boolean;
  comment: string;
}

export async function getHostAccess(): Promise<HostAccessRule[]> {
  const response = await request<{ rules: HostAccessRule[] }>('/api/host-access');
  return response.rules;
}

export async function putHostAccess(rules: HostAccessRule[]): Promise<HostAccessRule[]> {
  const response = await request<{ rules: HostAccessRule[] }>('/api/host-access', {
    method: 'PUT',
    body: { rules },
  });
  return response.rules;
}
