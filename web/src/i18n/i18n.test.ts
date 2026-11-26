import { afterEach, describe, expect, it, vi } from 'vitest';
import de from './de.json';
import en from './en.json';
import driversDe from './drivers.de.json';
import driversEn from './drivers.en.json';
import { driverText } from './dynamic';
import { OPENVPN_SCHEMA, WIREGUARD_SCHEMA } from '../test/fixtures';
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

describe('driver texts', () => {
  it('have identical key sets in de and en', () => {
    expect(Object.keys(driversDe).sort()).toEqual(Object.keys(driversEn).sort());
  });

  it.each([
    ['OpenVPN', OPENVPN_SCHEMA],
    ['WireGuard', WIREGUARD_SCHEMA],
  ])('cover every label of the %s form schema', (_name, schema) => {
    const keys = schema.sections.flatMap((section) => [
      section.labelKey,
      ...section.fields.flatMap((field) => [
        field.labelKey,
        ...(field.options ?? []).map((option) => option.labelKey),
      ]),
    ]);
    expect(keys.filter((key) => !(key in driversEn))).toEqual([]);
  });

  it('fall back to the key for unknown labels', () => {
    expect(driverText('de', 'openvpn.authMode.password')).toBe('Benutzername und Passwort');
    expect(driverText('de', 'nope.key')).toBe('nope.key');
  });
});
