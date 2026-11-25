import { request } from './client';

export interface SystemInfo {
  version: string;
}

export function getSystem(): Promise<SystemInfo> {
  return request<SystemInfo>('/api/system');
}
