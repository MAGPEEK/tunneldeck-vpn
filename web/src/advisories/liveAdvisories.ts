import type { Advisory } from '../api/profiles';

const UNENCRYPTED = 'unencrypted_data_channel';
const UNENCRYPTED_ALLOWED = 'unencrypted_data_channel_allowed';

/**
 * The advisories of a running tunnel, corrected by what it negotiated: a
 * profile that allows "cipher none" is only a danger while the tunnel
 * really runs without a cipher. With a negotiated cipher the finding
 * becomes a warning to remove "none" from the profile.
 */
export function liveAdvisories(
  advisories: readonly Advisory[],
  dataCipher: string | undefined,
): Advisory[] {
  const encrypted = dataCipher !== undefined && dataCipher !== '' && dataCipher !== 'none';
  if (!encrypted) {
    return [...advisories];
  }
  return advisories.map((advisory) =>
    advisory.code === UNENCRYPTED
      ? { ...advisory, code: UNENCRYPTED_ALLOWED, severity: 'warning' }
      : advisory,
  );
}
