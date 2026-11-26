/** The importer reads at most 1 MiB (internal/vpn/openvpn). */
export const MAX_PROFILE_FILE_BYTES = 1 << 20;

/** File types the picker offers and drag and drop accepts. */
export const PROFILE_FILE_ACCEPT = '.ovpn,.conf';

const PROFILE_FILE_EXTENSION = /\.(ovpn|conf)$/i;

/** Longest profile name the server accepts. */
const MAX_NAME_LENGTH = 64;

export function isProfileFileName(name: string): boolean {
  return PROFILE_FILE_EXTENSION.test(name);
}

/** "Office VPN.ovpn" → "Office VPN"; "" when nothing is left. */
export function profileNameFromFile(fileName: string): string {
  return fileName.replace(PROFILE_FILE_EXTENSION, '').trim().slice(0, MAX_NAME_LENGTH);
}

/**
 * Reads a profile file as text. UTF-8 is expected; files in a legacy
 * 8-bit encoding (for example Latin-1 umlauts in comments) are decoded as
 * Windows-1252 instead of turning their bytes into replacement characters.
 */
export async function readProfileFile(file: Blob): Promise<string> {
  const bytes = await file.arrayBuffer();
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return new TextDecoder('windows-1252').decode(bytes);
  }
}
