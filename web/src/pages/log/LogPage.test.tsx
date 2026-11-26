import { act, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { FakeEventSource } from '../../test/fakeEventSource';
import { makeStatus } from '../../test/fixtures';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

describe('LogPage', () => {
  it('shows the stored lines and appends lines from the event stream', async () => {
    renderApp(
      {
        'GET /api/session': { body: SIGNED_IN },
        'GET /api/connection': { body: makeStatus() },
        'GET /api/logs?tail=2000': {
          body: {
            lines: [{ time: '2026-11-25T10:00:00Z', level: 'info', text: 'TunnelDeck started' }],
          },
        },
      },
      '/log',
    );

    expect(await screen.findByRole('heading', { level: 1, name: 'Log' })).toBeInTheDocument();
    expect(await screen.findByText('TunnelDeck started')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Level' })).toBeInTheDocument();

    act(() => {
      FakeEventSource.latest().emit('log', {
        time: '2026-11-25T10:00:05Z',
        level: 'error',
        text: 'Something broke',
      });
    });
    expect(await screen.findByText('Something broke')).toBeInTheDocument();
  });
});
