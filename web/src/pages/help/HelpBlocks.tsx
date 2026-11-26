import { Fragment } from 'react';
import { ExternalLink } from '../../components/ExternalLink';
import type { Language } from '../../i18n';
import type { HelpBlock, HelpLinkTarget } from './content';
import { docUrl, REPORT_PROBLEM_URL } from './links';
import styles from './HelpPage.module.css';

/** Plain text in which `backtick spans` become code. */
export function RichText({ text }: { text: string }) {
  return text
    .split('`')
    .map((part, index) =>
      index % 2 === 1 ? <code key={index}>{part}</code> : <Fragment key={index}>{part}</Fragment>,
    );
}

interface LinkContext {
  version: string | undefined;
  language: Language;
}

function targetUrl(target: HelpLinkTarget, { version, language }: LinkContext): string {
  return target === 'issues' ? REPORT_PROBLEM_URL : docUrl(target, version, language);
}

function Block({ block, links }: { block: HelpBlock; links: LinkContext }) {
  switch (block.type) {
    case 'paragraph':
      return (
        <p>
          <RichText text={block.text} />
        </p>
      );
    case 'subheading':
      return <h3 className={styles.subheading}>{block.text}</h3>;
    case 'list':
      return (
        <ul>
          {block.items.map((item) => (
            <li key={item}>
              <RichText text={item} />
            </li>
          ))}
        </ul>
      );
    case 'terms':
      return (
        <dl className={styles.terms}>
          {block.items.map(({ term, text }) => (
            <div key={term}>
              <dt>
                <RichText text={term} />
              </dt>
              <dd>
                <RichText text={text} />
              </dd>
            </div>
          ))}
        </dl>
      );
    case 'link':
      return (
        <p>
          <ExternalLink href={targetUrl(block.target, links)}>{block.text}</ExternalLink>
        </p>
      );
  }
}

export function HelpBlocks({ blocks, links }: { blocks: HelpBlock[]; links: LinkContext }) {
  return (
    <div className={styles.blocks}>
      {blocks.map((block, index) => (
        <Block key={index} block={block} links={links} />
      ))}
    </div>
  );
}
