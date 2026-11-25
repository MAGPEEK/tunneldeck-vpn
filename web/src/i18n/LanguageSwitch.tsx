import { useTranslation } from 'react-i18next';
import { LANGUAGES, setLanguage } from './index';
import styles from './LanguageSwitch.module.css';

export function LanguageSwitch() {
  const { t, i18n } = useTranslation();
  return (
    <div role="group" aria-label={t('language.label')} className={styles.switch}>
      {LANGUAGES.map((language) => (
        <button
          key={language}
          type="button"
          lang={language}
          className={styles.option}
          aria-pressed={i18n.resolvedLanguage === language}
          title={t(`language.${language}`)}
          onClick={() => void setLanguage(language)}
        >
          {language.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
