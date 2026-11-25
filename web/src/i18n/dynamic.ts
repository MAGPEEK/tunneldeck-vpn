import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import driversDe from './drivers.de.json';
import driversEn from './drivers.en.json';

type LooseT = (key: string, options?: Record<string, unknown>) => string;

/**
 * Translates a key built at run time, such as `advisory.<code>` for a code
 * the server sent. Unknown keys give `fallback` (or the key itself).
 */
export function translateDynamic(
  t: TFunction,
  key: string,
  fallback?: string,
  values?: Record<string, unknown>,
): string {
  return (t as unknown as LooseT)(key, { defaultValue: fallback ?? key, ...values });
}

/**
 * Driver label keys (from FormSchema) are flat and may be prefixes of each
 * other ("openvpn.authMode" and "openvpn.authMode.password"), so they live
 * in their own flat files instead of the nested i18next resources.
 */
export const DRIVER_TEXTS: Record<string, Record<string, string>> = {
  de: driversDe,
  en: driversEn,
};

const FALLBACK_TEXTS: Record<string, string> = driversEn;

export function driverText(language: string | undefined, key: string): string {
  const texts = DRIVER_TEXTS[language ?? 'en'] ?? FALLBACK_TEXTS;
  return texts[key] ?? FALLBACK_TEXTS[key] ?? key;
}

/** `driverText` bound to the current language. */
export function useDriverText(): (key: string) => string {
  const { i18n } = useTranslation();
  const language = i18n.resolvedLanguage;
  return (key) => driverText(language, key);
}
