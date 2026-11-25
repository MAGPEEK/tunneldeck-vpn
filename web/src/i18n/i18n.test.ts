import { afterEach, describe, expect, it, vi } from 'vitest';
import de from './de.json';
import en from './en.json';
import { LANGUAGE_STORAGE_KEY, detectLanguage } from './index';

function keyPaths(value: unknown, prefix = ''): string[] {
  if (typeof value !== 'object' || value === null) {
    return [prefix];
  }
  return Object.entries(value).flatMap(([key, child]) =>
    keyPaths(child, prefix === '' ? key : `${prefix}.${key}`),
  );
}

describe('translations', () => {
  it('have identical key sets in de and en', () => {
    expect(keyPaths(de).sort()).toEqual(keyPaths(en).sort());
  });

  it('have no empty strings', () => {
    const values = [de, en].flatMap((file) =>
      keyPaths(file).map((path) =>
        path
          .split('.')
          .reduce<unknown>((node, key) => (node as Record<string, unknown>)[key], file),
      ),
    );
    expect(values.every((value) => typeof value === 'string' && value !== '')).toBe(true);
  });
});

describe('detectLanguage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('prefers the stored choice', () => {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, 'de');
    vi.spyOn(navigator, 'language', 'get').mockReturnValue('en-US');
    expect(detectLanguage()).toBe('de');
  });

  it('falls back to the browser language', () => {
    vi.spyOn(navigator, 'language', 'get').mockReturnValue('de-AT');
    expect(detectLanguage()).toBe('de');
  });

  it('falls back to English for unsupported languages', () => {
    vi.spyOn(navigator, 'language', 'get').mockReturnValue('fr-FR');
    expect(detectLanguage()).toBe('en');
  });
});
