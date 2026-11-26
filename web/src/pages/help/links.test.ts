import { describe, expect, it } from 'vitest';
import {
  docUrl,
  isReleaseVersion,
  licenseUrl,
  readmeUrl,
  releaseNotesUrl,
  sourceRef,
} from './links';

const REPO = 'https://github.com/MAGPEEK/tunneldeck-vpn';

describe('isReleaseVersion', () => {
  it.each([
    ['0.2.0', true],
    ['1.10.3', true],
    ['0.2.0-alpha.5', true],
    ['dev', false],
    ['v0.2.0', false],
    ['0.2.0-alpha.5-3-gabc1234', false],
    ['0.2.0-beta.1', false],
    ['0.2', false],
    ['', false],
    [undefined, false],
  ])('%s → %s', (version, expected) => {
    expect(isReleaseVersion(version)).toBe(expected);
  });
});

describe('sourceRef', () => {
  it.each([
    ['0.2.0-alpha.5', 'v0.2.0-alpha.5'],
    ['1.0.0', 'v1.0.0'],
    ['dev', 'main'],
    [undefined, 'main'],
  ])('%s → %s', (version, expected) => {
    expect(sourceRef(version)).toBe(expected);
  });
});

describe('docUrl', () => {
  it.each([
    ['0.2.0', 'en', `${REPO}/blob/v0.2.0/docs/linux.md`],
    ['0.2.0-alpha.5', 'de', `${REPO}/blob/v0.2.0-alpha.5/docs/linux.de.md`],
    ['dev', 'en', `${REPO}/blob/main/docs/linux.md`],
    [undefined, 'de', `${REPO}/blob/main/docs/linux.de.md`],
  ] as const)('version %s, language %s', (version, language, expected) => {
    expect(docUrl('linux', version, language)).toBe(expected);
  });
});

describe('other links', () => {
  it('point the README and licence at the installed version', () => {
    expect(readmeUrl('1.2.3', 'de')).toBe(`${REPO}/blob/v1.2.3/README.de.md`);
    expect(readmeUrl('dev', 'en')).toBe(`${REPO}/blob/main/README.md`);
    expect(licenseUrl('1.2.3')).toBe(`${REPO}/blob/v1.2.3/LICENSE`);
  });

  it('link the release notes of a release and the release list otherwise', () => {
    expect(releaseNotesUrl('0.2.0-alpha.5')).toBe(`${REPO}/releases/tag/v0.2.0-alpha.5`);
    expect(releaseNotesUrl('dev')).toBe(`${REPO}/releases`);
  });
});
