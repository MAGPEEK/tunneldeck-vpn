import { request } from './client';

export type Protocol = string;

export type FieldType =
  'text' | 'number' | 'select' | 'secret' | 'textarea' | 'stringList' | 'bool';

/** A setting value as JSON allows it in a profile's settings map. */
export type SettingValue = string | number | boolean | string[];

export type Settings = Record<string, SettingValue>;

export interface SchemaOption {
  value: string;
  labelKey: string;
  /** Values that choosing this option pre-fills into other setting fields, by field key (a template). */
  presets?: Settings;
}

/** A setting holds one of `equals`, or the secret field `secret` has a value. */
export type VisibleWhen = { key: string; equals: string[] } | { secret: string };

export interface SchemaField {
  key: string;
  type: FieldType;
  labelKey: string;
  required?: boolean;
  multiline?: boolean;
  options?: SchemaOption[];
  default?: SettingValue;
  visibleWhen?: VisibleWhen;
  placeholder?: string;
  /** `base64`: a multi-line secret holding a binary file; offer a file picker and send base64. */
  encoding?: 'base64';
}

export interface SchemaSection {
  key: string;
  labelKey: string;
  fields: SchemaField[];
}

export interface FormSchema {
  sections: SchemaSection[];
}

export interface Driver {
  protocol: Protocol;
  schema: FormSchema;
}

export type AdvisorySeverity = 'info' | 'warning' | 'danger';

export interface Advisory {
  code: string;
  severity: AdvisorySeverity;
  field?: string;
}

export interface DailyReconnect {
  enabled: boolean;
  time: string;
}

export interface Profile {
  id: string;
  name: string;
  protocol: Protocol;
  settings: Settings;
  secrets: Record<string, { hasValue: boolean }>;
  dailyReconnect: DailyReconnect;
  /** The address the provider assigns to this connection (IPv4 or host name); "" when not set. */
  publicAddress?: string;
  createdAt: string;
  updatedAt: string;
  advisories: Advisory[];
  /** Values the driver derives from stored secrets for display, e.g. WireGuard's `publicKey`. */
  derived?: Record<string, string>;
}

export interface ProfileRequest {
  name: string;
  protocol: Protocol;
  settings: Settings;
  secrets: Record<string, string>;
  clearSecrets: string[];
  dailyReconnect: DailyReconnect;
  publicAddress: string;
}

export type ImportSeverity = 'info' | 'warning' | 'rejected';

export interface ImportWarning {
  code: string;
  severity: ImportSeverity;
  directive?: string;
  line?: number;
  /** The file a directive refers to, for file_reference. */
  file?: string;
  message: string;
}

/** A parsed configuration file. Secrets are only ever sent back to the uploading client. */
export interface ImportDraft {
  settings: Settings;
  secrets: Record<string, string>;
  warnings: ImportWarning[];
  /** Setting and secret keys the file left empty, in form order. */
  missing: string[];
}

export function getDrivers(): Promise<Driver[]> {
  return request<Driver[]>('/api/drivers');
}

/** A fresh key pair; the server stores nothing, the private key is sent back with the profile. */
export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

export function generateKeyPair(protocol: Protocol): Promise<KeyPair> {
  return request<KeyPair>(`/api/drivers/${encodeURIComponent(protocol)}/keypair`, {
    method: 'POST',
  });
}

export function getProfiles(): Promise<Profile[]> {
  return request<Profile[]>('/api/profiles');
}

export function getProfile(id: string): Promise<Profile> {
  return request<Profile>(`/api/profiles/${encodeURIComponent(id)}`);
}

export function createProfile(body: ProfileRequest): Promise<Profile> {
  return request<Profile>('/api/profiles', { method: 'POST', body });
}

export function updateProfile(id: string, body: ProfileRequest): Promise<Profile> {
  return request<Profile>(`/api/profiles/${encodeURIComponent(id)}`, { method: 'PUT', body });
}

export function deleteProfile(id: string): Promise<void> {
  return request<undefined>(`/api/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export function importProfile(protocol: Protocol, text: string): Promise<ImportDraft> {
  return request<ImportDraft>('/api/profiles/import', {
    method: 'POST',
    body: { protocol, text },
  });
}
