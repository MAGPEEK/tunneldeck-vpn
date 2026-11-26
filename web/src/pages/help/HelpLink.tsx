import { CircleHelp } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { HelpSectionId } from './content';
import styles from './HelpLink.module.css';

/** The "?" in a page header: opens the matching section of the Help page. */
export function HelpLink({ section }: { section: HelpSectionId }) {
  const { t } = useTranslation();
  const label = t('help.forThisPage');
  return (
    <Link to={`/help#${section}`} className={styles.link} aria-label={label} title={label}>
      <CircleHelp size={18} aria-hidden="true" />
    </Link>
  );
}
