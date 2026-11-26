import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation } from 'react-router';
import { Card } from '../../components/Card';
import type { Language } from '../../i18n';
import { Page } from '../../layout/Page';
import { useSystem } from '../../queries/queries';
import { AboutSection } from './AboutSection';
import { HELP_SECTIONS, type HelpContent, type HelpSectionId } from './content';
import { HELP_CONTENT_DE } from './content.de';
import { HELP_CONTENT_EN } from './content.en';
import { HelpBlocks } from './HelpBlocks';
import styles from './HelpPage.module.css';

const CONTENT: Record<Language, HelpContent> = { de: HELP_CONTENT_DE, en: HELP_CONTENT_EN };

/** Scrolls to the section named in the URL hash, also after the page loaded lazily. */
function useScrollToHash() {
  const { hash } = useLocation();
  useEffect(() => {
    const id = decodeURIComponent(hash.slice(1));
    if (id !== '') {
      document.getElementById(id)?.scrollIntoView?.();
    }
  }, [hash]);
}

function TableOfContents() {
  const { t } = useTranslation();
  return (
    <Card title={t('help.contents')}>
      <nav aria-label={t('help.contents')}>
        <ol className={styles.toc}>
          {HELP_SECTIONS.map((id) => (
            <li key={id}>
              <a href={`#${id}`}>{t(`help.sections.${id}`)}</a>
            </li>
          ))}
        </ol>
      </nav>
    </Card>
  );
}

interface SectionBodyProps {
  id: HelpSectionId;
  version: string | undefined;
  language: Language;
}

function SectionBody({ id, version, language }: SectionBodyProps) {
  if (id === 'about') {
    return <AboutSection version={version} language={language} />;
  }
  return <HelpBlocks blocks={CONTENT[language][id]} links={{ version, language }} />;
}

/** In-app documentation; its GitHub links point at the installed version. */
export function HelpPage() {
  const { t, i18n } = useTranslation();
  const language: Language = i18n.resolvedLanguage === 'de' ? 'de' : 'en';
  const version = useSystem().data?.version;
  useScrollToHash();
  return (
    <Page title={t('pages.help.title')}>
      <div className={styles.layout}>
        <TableOfContents />
        {HELP_SECTIONS.map((id) => (
          <div key={id} id={id} className={styles.anchor}>
            <Card title={t(`help.sections.${id}`)}>
              <SectionBody id={id} version={version} language={language} />
            </Card>
          </div>
        ))}
      </div>
    </Page>
  );
}
