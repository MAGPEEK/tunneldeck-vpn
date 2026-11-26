import { describe, expect, it } from 'vitest';
import type { Advisory } from '../api/profiles';
import { liveAdvisories } from './liveAdvisories';

const unencrypted: Advisory = {
  code: 'unencrypted_data_channel',
  severity: 'danger',
  field: 'cipher',
};
const noDco: Advisory = { code: 'no_dco', severity: 'info' };

describe('liveAdvisories', () => {
  it.each([
    ['unknown', undefined],
    ['empty', ''],
    ['none', 'none'],
  ])('keeps the danger while the negotiated cipher is %s', (_, cipher) => {
    expect(liveAdvisories([unencrypted, noDco], cipher)).toEqual([unencrypted, noDco]);
  });

  it('turns the danger into a warning once a cipher was negotiated', () => {
    expect(liveAdvisories([unencrypted, noDco], 'CHACHA20-POLY1305')).toEqual([
      { code: 'unencrypted_data_channel_allowed', severity: 'warning', field: 'cipher' },
      noDco,
    ]);
  });
});
