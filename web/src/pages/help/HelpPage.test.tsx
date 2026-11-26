import { act, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { i18n } from '../../i18n';
import { SIGNED_IN, renderApp } from '../../test/renderApp';
import { HELP_SECTIONS } from './content';
import { HELP_CONTENT_DE } from './content.de';
import { HELP_CONTENT_EN } from './content.en';

const REPO = 'https://github.com/MAGPEEK/tunneldeck-vpn';

function renderHelp(version: string, path = '/help') {
  return renderApp(
    {
      'GET /api/session': { body: SIGNED_IN },
      'GET /api/system': {
        body: {
          version,
          listenAddress: '192.168.1.2:8194',
          serverTime: '2026-11-25T10:00:00Z',
          timeZone: 'UTC',
          checks: [],
        },
      },
    },
    path,
  );
}

async function linkTo(name: string): Promise<HTMLElement> {
  return screen.findByRole('link', { name });
}

describe('help content', () => {
  it('has the same sections in German and English, each with text', () => {
    const textSections = HELP_SECTIONS.filter((id) => id !== 'about');
    expect(Object.keys(HELP_CONTENT_DE).sort()).toEqual([...textSections].sort());
    expect(Object.keys(HELP_CONTENT_EN).sort()).toEqual([...textSections].sort());
    for (const id of textSections) {
      expect(HELP_CONTENT_DE[id].length).toBeGreaterThan(0);
      expect(HELP_CONTENT_EN[id].length).toBeGreaterThan(0);
    }
  });

  it('has balanced code spans', () => {
    const texts = [HELP_CONTENT_DE, HELP_CONTENT_EN].flatMap((content) =>
      Object.values(content).flatMap((blocks) =>
        blocks.flatMap((block) => {
          switch (block.type) {
            case 'list':
              return block.items;
            case 'terms':
              return block.items.flatMap(({ term, text }) => [term, text]);
            default:
              return [block.text];
          }
        }),
      ),
    );
    expect(texts.filter((text) => text.split('`').length % 2 === 0)).toEqual([]);
  });
});

describe('HelpPage', () => {
  it.each(['en', 'de'] as const)(
    'links every table-of-contents entry to a section (%s)',
    async (language) => {
      await act(() => i18n.changeLanguage(language));
      renderHelp('1.2.3');
      const toc = await screen.findByRole('navigation', {
        name: language === 'de' ? 'Inhalt' : 'Contents',
      });
      const anchors = within(toc)
        .getAllByRole('link')
        .map((link) => link.getAttribute('href'));
      expect(anchors).toEqual(HELP_SECTIONS.map((id) => `#${id}`));
      for (const id of HELP_SECTIONS) {
        const section = document.getElementById(id);
        expect(section).not.toBeNull();
        expect(within(section as HTMLElement).getByRole('heading', { level: 2 })).toHaveTextContent(
          i18n.t(`help.sections.${id}`),
        );
      }
    },
  );

  it('points GitHub links at the installed release and opens them in a new tab', async () => {
    renderHelp('0.2.0-alpha.5');
    expect(await screen.findByText('0.2.0-alpha.5')).toBeInTheDocument();
    expect(await linkTo('Every check in detail, with fixes for Linux and DSM')).toHaveAttribute(
      'href',
      `${REPO}/blob/v0.2.0-alpha.5/docs/system-checks.md`,
    );
    expect(screen.getByRole('link', { name: 'Release notes of this version' })).toHaveAttribute(
      'href',
      `${REPO}/releases/tag/v0.2.0-alpha.5`,
    );
    expect(screen.getByRole('link', { name: 'Report a problem' })).toHaveAttribute(
      'href',
      `${REPO}/issues/new`,
    );
    const external = screen
      .getAllByRole('link')
      .filter((link) => link.getAttribute('href')?.startsWith('https://'));
    expect(external.length).toBeGreaterThan(5);
    for (const link of external) {
      expect(link).toHaveAttribute('target', '_blank');
      expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    }
  });

  it('links the German guides on main for a development build in German', async () => {
    await act(() => i18n.changeLanguage('de'));
    renderHelp('dev');
    expect(await linkTo('Alle Prüfungen im Detail, mit Abhilfe für Linux und DSM')).toHaveAttribute(
      'href',
      `${REPO}/blob/main/docs/system-checks.de.md`,
    );
    expect(screen.getByRole('link', { name: 'Versionen' })).toHaveAttribute(
      'href',
      `${REPO}/releases`,
    );
  });

  it('scrolls to the section named in the address', async () => {
    const scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    renderHelp('1.2.3', '/help#firewall');
    await screen.findByRole('heading', { level: 1, name: 'Help' });
    expect(scrollIntoView).toHaveBeenCalled();
    expect(scrollIntoView.mock.contexts[0]).toBe(document.getElementById('firewall'));
  });
});

afterEach(() => {
  Reflect.deleteProperty(Element.prototype, 'scrollIntoView');
});
