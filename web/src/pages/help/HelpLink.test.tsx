import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

describe('contextual help', () => {
  it.each([
    ['/profiles', 'Profiles', '/help#profiles'],
    ['/firewall', 'Firewall', '/help#firewall'],
    ['/system', 'System', '/help#system-checks'],
    ['/log', 'Log', '/help#troubleshooting'],
  ])('%s links its header to %s help', async (path, title, target) => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } }, path);
    await screen.findByRole('heading', { level: 1, name: title });
    expect(await screen.findByRole('link', { name: 'Help for this page' })).toHaveAttribute(
      'href',
      target,
    );
  });

  it('opens the help page at the matching section', async () => {
    renderApp({ 'GET /api/session': { body: SIGNED_IN } }, '/log');
    fireEvent.click(await screen.findByRole('link', { name: 'Help for this page' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Help' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/help');
    expect(window.location.hash).toBe('#troubleshooting');
  });
});
