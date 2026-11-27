import type { HelpDoc } from './links';

/** Section anchors of the Help page, in display order; the same in every language. */
export const HELP_SECTIONS = [
  'getting-started',
  'profiles',
  'connecting',
  'firewall',
  'remote-access',
  'system-checks',
  'sign-ins',
  'troubleshooting',
  'admin-reset',
  'about',
] as const;
export type HelpSectionId = (typeof HELP_SECTIONS)[number];

/** Sections whose text lives in the content files; "about" is built from live data. */
export type TextSectionId = Exclude<HelpSectionId, 'about'>;

/** A link target on GitHub: a guide in docs/ or the issue form. */
export type HelpLinkTarget = HelpDoc | 'issues';

/** Text may contain `code spans` in backticks; nothing else is interpreted. */
export type HelpBlock =
  | { type: 'paragraph'; text: string }
  | { type: 'subheading'; text: string }
  | { type: 'list'; items: string[] }
  | { type: 'terms'; items: { term: string; text: string }[] }
  | { type: 'link'; target: HelpLinkTarget; text: string };

export type HelpContent = Record<TextSectionId, HelpBlock[]>;
