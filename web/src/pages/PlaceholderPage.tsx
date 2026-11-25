import { useTranslation } from 'react-i18next';
import { EmptyState } from '../components/EmptyState';
import { Page } from '../layout/Page';

export interface PlaceholderPageProps {
  section: 'dashboard' | 'profiles' | 'hostAccess' | 'system';
}

/** Title and a one-line note until the real page for this section exists. */
export function PlaceholderPage({ section }: PlaceholderPageProps) {
  const { t } = useTranslation();
  return (
    <Page title={t(`pages.${section}.title`)}>
      <EmptyState title={t('pages.placeholderTitle')} body={t(`pages.${section}.body`)} />
    </Page>
  );
}
