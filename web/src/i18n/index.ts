import i18next from 'i18next';
import { initReactI18next } from 'react-i18next';
import de from './de.json';
import en from './en.json';

export const LANGUAGES = ['de', 'en'] as const;
export type Language = (typeof LANGUAGES)[number];

export const LANGUAGE_STORAGE_KEY = 'tunneldeck.language';
const FALLBACK_LANGUAGE: Language = 'en';

export const resources = {
  de: { translation: de },
  en: { translation: en },
} as const;

function isLanguage(value: string | null | undefined): value is Language {
  return LANGUAGES.some((language) => language === value);
}

function readStoredLanguage(): string | null {
  try {
    return localStorage.getItem(LANGUAGE_STORAGE_KEY);
  } catch {
    return null;
  }
}

/** Stored choice, then browser language, then English. */
export function detectLanguage(): Language {
  const stored = readStoredLanguage();
  if (isLanguage(stored)) {
    return stored;
  }
  const browser = navigator.language.split('-')[0]?.toLowerCase();
  return isLanguage(browser) ? browser : FALLBACK_LANGUAGE;
}

export async function setLanguage(language: Language): Promise<void> {
  try {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
  } catch {
    // Storage can be unavailable (private mode); the choice then lasts for this page only.
  }
  await i18next.changeLanguage(language);
}

i18next.on('languageChanged', (language) => {
  document.documentElement.lang = language;
});

void i18next.use(initReactI18next).init({
  resources,
  lng: detectLanguage(),
  fallbackLng: FALLBACK_LANGUAGE,
  supportedLngs: LANGUAGES,
  interpolation: { escapeValue: false },
  initAsync: false,
  returnNull: false,
});

export { i18next as i18n };
