import { useTranslation } from 'react-i18next';
import { ExternalLink } from '../../components/ExternalLink';
import type { Language } from '../../i18n';
import {
  docUrl,
  HELP_DOCS,
  isReleaseVersion,
  licenseUrl,
  readmeUrl,
  releaseNotesUrl,
  REPORT_PROBLEM_URL,
  REPOSITORY_URL,
  sourceRef,
} from './links';
import styles from './HelpPage.module.css';

export interface AboutSectionProps {
  version: string | undefined;
  language: Language;
}

/** Installed version, licence and the GitHub links for exactly this version. */
export function AboutSection({ version, language }: AboutSectionProps) {
  const { t } = useTranslation();
  const release = isReleaseVersion(version);
  return (
    <div className={styles.blocks}>
      <dl className={styles.values}>
        <dt>{t('help.about.version')}</dt>
        <dd className={styles.mono}>{version ?? t('help.about.versionUnknown')}</dd>
        <dt>{t('help.about.license')}</dt>
        <dd>
          <ExternalLink href={licenseUrl(version)}>MIT</ExternalLink>
        </dd>
      </dl>
      <p className={styles.secondary}>
        {release
          ? t('help.about.linksRelease', { ref: sourceRef(version) })
          : t('help.about.linksMain')}
      </p>
      <ul>
        <li>
          <ExternalLink href={releaseNotesUrl(version)}>
            {release ? t('help.about.releaseNotes') : t('help.about.releases')}
          </ExternalLink>
        </li>
        <li>
          <ExternalLink href={REPOSITORY_URL}>{t('help.about.repository')}</ExternalLink>
        </li>
        <li>
          <ExternalLink href={REPORT_PROBLEM_URL}>{t('help.about.reportProblem')}</ExternalLink>
        </li>
      </ul>
      <h3 className={styles.subheading}>{t('help.about.documentation')}</h3>
      <ul>
        <li>
          <ExternalLink href={readmeUrl(version, language)}>{t('help.docs.readme')}</ExternalLink>
        </li>
        {HELP_DOCS.map((doc) => (
          <li key={doc}>
            <ExternalLink href={docUrl(doc, version, language)}>
              {t(`help.docs.${doc}`)}
            </ExternalLink>
          </li>
        ))}
      </ul>
    </div>
  );
}
