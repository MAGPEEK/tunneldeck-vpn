import { isApiError, request } from './client';

export type CertificateSource = 'selfSigned' | 'uploaded';

export interface Certificate {
  subject: string;
  notBefore: string;
  notAfter: string;
  fingerprintSha256: string;
  selfSigned: boolean;
}

/** GET /api/remote-access (SPEC §8.1). */
export interface RemoteAccess {
  enabled: boolean;
  port: number;
  certificateSource: CertificateSource;
  certificate: Certificate | null;
  listening: boolean;
  lastError?: string;
}

export interface RemoteAccessSettings {
  enabled: boolean;
  port: number;
  certificateSource: CertificateSource;
}

export interface CertificateUpload {
  certificatePem: string;
  keyPem: string;
}

/** Resolves to null when this build has no remote access (404). */
export async function getRemoteAccess(): Promise<RemoteAccess | null> {
  try {
    return await request<RemoteAccess>('/api/remote-access');
  } catch (error) {
    if (isApiError(error) && error.status === 404) {
      return null;
    }
    throw error;
  }
}

export function putRemoteAccess(body: RemoteAccessSettings): Promise<RemoteAccess> {
  return request<RemoteAccess>('/api/remote-access', { method: 'PUT', body });
}

export function uploadCertificate(body: CertificateUpload): Promise<RemoteAccess> {
  return request<RemoteAccess>('/api/remote-access/certificate', { method: 'POST', body });
}
