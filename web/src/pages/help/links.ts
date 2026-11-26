import type { Language } from '../../i18n';

export const REPOSITORY_URL = 'https://github.com/MAGPEEK/tunneldeck-vpn';
export const REPORT_PROBLEM_URL = `${REPOSITORY_URL}/issues/new`;

/** Guides in docs/ that exist in English (<name>.md) and German (<name>.de.md). */
export const HELP_DOCS = [
  'linux',
  'synology',
  'migrate-from-rut240',
  'system-checks',
  'reset-admin',
] as const;
export type HelpDoc = (typeof HELP_DOCS)[number];

/** A release tag without its "v": X.Y.Z or X.Y.Z-alpha.N. Anything else is a development build. */
const RELEASE_VERSION = /^\d+\.\d+\.\d+(?:-alpha\.\d+)?$/;

export function isReleaseVersion(version: string | undefined): version is string {
  return version !== undefined && RELEASE_VERSION.test(version);
}

/** The git ref the links point at: the release tag of the installed version, else main. */
export function sourceRef(version: string | undefined): string {
  return isReleaseVersion(version) ? `v${version}` : 'main';
}

function languageSuffix(language: Language): string {
  return language === 'de' ? '.de' : '';
}

export function docUrl(doc: HelpDoc, version: string | undefined, language: Language): string {
  return `${REPOSITORY_URL}/blob/${sourceRef(version)}/docs/${doc}${languageSuffix(language)}.md`;
}

export function readmeUrl(version: string | undefined, language: Language): string {
  return `${REPOSITORY_URL}/blob/${sourceRef(version)}/README${languageSuffix(language)}.md`;
}

export function licenseUrl(version: string | undefined): string {
  return `${REPOSITORY_URL}/blob/${sourceRef(version)}/LICENSE`;
}

/** The release notes of the installed release; the list of releases for a development build. */
export function releaseNotesUrl(version: string | undefined): string {
  return isReleaseVersion(version)
    ? `${REPOSITORY_URL}/releases/tag/v${version}`
    : `${REPOSITORY_URL}/releases`;
}
